// Copyright 2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/dns/dnsmessage"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// Taken from
// https://cs.opensource.google/go/x/net/+/refs/tags/v0.27.0:dns/dnsmessage/message.go
// to trim Type and Rcode prefixes.
// More information about the DNS message format can be found in
// https://datatracker.ietf.org/doc/html/rfc1035 and
// https://datatracker.ietf.org/doc/html/rfc3596.

// A Type is a type of DNS request and response.
type Type uint16

const (
	// ResourceHeader.Type and Question.Type
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
	TypeSRV   Type = 33
	TypeOPT   Type = 41

	// Question.Type
	TypeWKS   Type = 11
	TypeHINFO Type = 13
	TypeMINFO Type = 14
	TypeAXFR  Type = 252
	TypeALL   Type = 255
)

var typeNames = map[Type]string{
	TypeA:     "A",
	TypeNS:    "NS",
	TypeCNAME: "CNAME",
	TypeSOA:   "SOA",
	TypePTR:   "PTR",
	TypeMX:    "MX",
	TypeTXT:   "TXT",
	TypeAAAA:  "AAAA",
	TypeSRV:   "SRV",
	TypeOPT:   "OPT",
	TypeWKS:   "WKS",
	TypeHINFO: "HINFO",
	TypeMINFO: "MINFO",
	TypeAXFR:  "AXFR",
	TypeALL:   "ALL",
}

// String implements fmt.Stringer.String.
func (t Type) String() string {
	if n, ok := typeNames[t]; ok {
		return n
	}
	return fmt.Sprintf("%d", t)
}

// An RCode is a DNS response status code.
type RCode uint16

// Header.RCode values.
const (
	RCodeSuccess        RCode = 0 // NoError
	RCodeFormatError    RCode = 1 // FormErr
	RCodeServerFailure  RCode = 2 // ServFail
	RCodeNameError      RCode = 3 // NXDomain
	RCodeNotImplemented RCode = 4 // NotImp
	RCodeRefused        RCode = 5 // Refused
)

var rCodeNames = map[RCode]string{
	RCodeSuccess:        "Success",
	RCodeFormatError:    "FormatError",
	RCodeServerFailure:  "ServerFailure",
	RCodeNameError:      "NameError",
	RCodeNotImplemented: "NotImplemented",
	RCodeRefused:        "Refused",
}

// String implements fmt.Stringer.String.
func (r RCode) String() string {
	if n, ok := rCodeNames[r]; ok {
		return n
	}
	return fmt.Sprintf("%d", r)
}

// https://www.iana.org/assignments/dns-parameters/extended-dns-error-codes.csv
var edeNames = map[uint16]string{
	0:  "Other Error",
	1:  "Unsupported DNSKEY Algorithm",
	2:  "Unsupported DS Digest Type",
	3:  "Stale Answer",
	4:  "Forged Answer",
	5:  "DNSSEC Indeterminate",
	6:  "DNSSEC Bogus",
	7:  "Signature Expired",
	8:  "Signature Not Yet Valid",
	9:  "DNSKEY Missing",
	10: "RRSIGs Missing",
	11: "No Zone Key Bit Set",
	12: "NSEC Missing",
	13: "Cached Error",
	14: "Not Ready",
	15: "Blocked",
	16: "Censored",
	17: "Filtered",
	18: "Prohibited",
	19: "Stale NXDomain Answer",
	20: "Not Authoritative",
	21: "Not Supported",
	22: "No Reachable Authority",
	23: "Network Error",
	24: "Invalid Data",
	25: "Signature Expired before Valid",
	26: "Too Early",
	27: "Unsupported NSEC3 Iterations Value",
	28: "Unable to conform to policy",
	29: "Synthesized",
	30: "Invalid Query Type",
	31: "Rate Limited",
	32: "Over Quota",
	33: "Negative Trust Anchor",
	34: "New Delegation Only",
	35: "Blocked by Upstream DNS Server",
}

func extendedDNSErrors(msg *dnsmessage.Message) (string, error) {
	const edeOptionCode = 15 // RFC 8914
	var entries []string
	var errs []error
	for _, additional := range msg.Additionals {
		opt, ok := additional.Body.(*dnsmessage.OPTResource)
		if !ok {
			continue
		}
		for _, option := range opt.Options {
			if option.Code != edeOptionCode {
				continue
			}
			if len(option.Data) < 2 {
				errs = append(errs, fmt.Errorf("EDE option too short: got %d bytes, need at least 2", len(option.Data)))
				continue
			}
			code := binary.BigEndian.Uint16(option.Data)
			entry := fmt.Sprintf("%d", code)
			if name, ok := edeNames[code]; ok {
				entry += " (" + name + ")"
			}
			if len(option.Data) > 2 {
				if utf8.Valid(option.Data[2:]) {
					// Quote untrusted text to escape control characters and delimiters.
					entry += fmt.Sprintf(": %q", string(option.Data[2:]))
				} else {
					errs = append(errs, fmt.Errorf("EDE code %d has invalid UTF-8 extra text", code))
				}
			}
			entries = append(entries, entry)
		}
	}
	return strings.Join(entries, "; "), errors.Join(errs...)
}

var payload []byte

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	ds, err := api.GetDataSource("dns")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}

	dataF, err := ds.GetField("data")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	lenF, err := ds.GetField("data_len")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	dnsOffF, err := ds.GetField("dns_off")
	if err != nil {
		api.Warnf("failed to get field: %s", err)
		return 1
	}

	idF, err := ds.AddField("id", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	qrRawF, err := ds.AddField("qr_raw", api.Kind_Bool)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	qrF, err := ds.AddField("qr", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	qtypeRawF, err := ds.AddField("qtype_raw", api.Kind_Uint16)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	qtypeF, err := ds.AddField("qtype", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	nameF, err := ds.AddField("name", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	rcodeRawF, err := ds.AddField("rcode_raw", api.Kind_Uint16)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	rcodeF, err := ds.AddField("rcode", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	edeF, err := ds.AddField("ede", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	numAnswersF, err := ds.AddField("num_answers", api.Kind_Int32)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	addressesF, err := ds.AddField("addresses", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	TruncatedF, err := ds.AddField("tc", api.Kind_Bool)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	RecursionAvailableF, err := ds.AddField("ra", api.Kind_Bool)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	RecursionDesiredF, err := ds.AddField("rd", api.Kind_Bool)
	if err != nil {
		api.Warnf("failed to add field: %s", err)
		return 1
	}

	payload = make([]byte, 65536) // UDP packets cannot be larger

	ds.Subscribe(func(source api.DataSource, data api.Data) {
		// Get all fields sent by ebpf
		payloadLen, err := lenF.Uint32(data)
		if err != nil {
			api.Warnf("failed to get data_len: %s", err)
			return
		}
		dnsOff, err := dnsOffF.Uint16(data)
		if err != nil {
			api.Warnf("failed to get dns_off: %s", err)
			return
		}

		if payloadLen < uint32(dnsOff) {
			api.Warnf("packet too short: dataLen: %d < dnsOff: %d", payloadLen, dnsOff)
			return
		}

		n, err := dataF.Bytes(data, payload)
		if err != nil {
			api.Warnf("failed to get data: %s", err)
			return
		}

		if n == 0 {
			api.Warnf("empty data")
			return
		}

		msg := dnsmessage.Message{}
		if err := msg.Unpack(payload[dnsOff:n]); err != nil {
			api.Warnf("failed to unpack dns message: %s", err)
			return
		}

		idF.SetString(data, fmt.Sprintf("%.4x", msg.ID))

		qrRawF.SetBool(data, msg.Header.Response)
		if msg.Header.Response {
			rcodeRawF.SetUint16(data, uint16(msg.Header.RCode))
			rcodeF.SetString(data, RCode(msg.Header.RCode).String())
			qrF.SetString(data, "R")
		} else {
			qrF.SetString(data, "Q")
		}

		TruncatedF.SetBool(data, msg.Header.Truncated)

		RecursionAvailableF.SetBool(data, msg.Header.RecursionAvailable)

		RecursionDesiredF.SetBool(data, msg.Header.RecursionDesired)

		if len(msg.Questions) > 0 {
			question := msg.Questions[0]
			qtypeRawF.SetUint16(data, uint16(question.Type))
			qtypeF.SetString(data, Type(question.Type).String())
			nameF.SetString(data, question.Name.String())
		}

		numAnswersF.SetInt32(data, int32(len(msg.Answers)))

		var addresses []string

		for _, answer := range msg.Answers {
			var str string
			switch answer.Header.Type {
			case dnsmessage.TypeA:
				ipv4 := answer.Body.(*dnsmessage.AResource)
				str = net.IP(ipv4.A[:]).String()
			case dnsmessage.TypeAAAA:
				ipv6 := answer.Body.(*dnsmessage.AAAAResource)
				str = net.IP(ipv6.AAAA[:]).String()
			}
			if str != "" {
				addresses = append(addresses, str)
			}
		}

		addressesF.SetString(data, strings.Join(addresses, ","))

		ede, err := extendedDNSErrors(&msg)
		if err != nil {
			api.Warnf("failed to decode extended DNS errors: %s", err)
		}
		if err := edeF.SetString(data, ede); err != nil {
			api.Warnf("failed to set ede: %s", err)
		}
	}, 0)

	return 0
}

func main() {}
