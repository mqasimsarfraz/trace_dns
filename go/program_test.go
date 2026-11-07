// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Inspektor Gadget authors

package main

import (
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestExtendedDNSErrors(t *testing.T) {
	tests := []struct {
		name     string
		response bool
		rcode    dnsmessage.RCode
		options  []dnsmessage.Option
		want     string
		wantErr  string
	}{
		{
			name: "query without EDNS",
		},
		{
			name:     "response without EDNS",
			response: true,
		},
		{
			name:     "unrelated EDNS option",
			response: true,
			options:  []dnsmessage.Option{{Code: 12, Data: []byte{0, 0}}},
		},
		{
			name:     "DNSSEC failure with extra text",
			response: true,
			rcode:    dnsmessage.RCodeServerFailure,
			options:  []dnsmessage.Option{{Code: 15, Data: append([]byte{0, 6}, []byte("validation failed")...)}},
			want:     `6 (DNSSEC Bogus): "validation failed"`,
		},
		{
			name:     "successful response with EDE and no extra text",
			response: true,
			options:  []dnsmessage.Option{{Code: 15, Data: []byte{0, 3}}},
			want:     "3 (Stale Answer)",
		},
		{
			name:     "zero is a valid info code",
			response: true,
			options:  []dnsmessage.Option{{Code: 15, Data: []byte{0, 0}}},
			want:     "0 (Other Error)",
		},
		{
			name:     "multiple errors with unknown and private codes",
			response: true,
			options: []dnsmessage.Option{
				{Code: 15, Data: []byte{0, 23}},
				{Code: 12, Data: []byte{0}},
				{Code: 15, Data: []byte{1, 0}},
				{Code: 15, Data: append([]byte{0xfd, 0xe8}, []byte("private")...)},
			},
			want: `23 (Network Error); 256; 65000: "private"`,
		},
		{
			name:     "short options do not hide later errors",
			response: true,
			options: []dnsmessage.Option{
				{Code: 15},
				{Code: 15, Data: []byte{0}},
				{Code: 15, Data: []byte{0, 15}},
			},
			want:    "15 (Blocked)",
			wantErr: "EDE option too short: got 0 bytes, need at least 2\nEDE option too short: got 1 bytes, need at least 2",
		},
		{
			name:     "only malformed EDE",
			response: true,
			options:  []dnsmessage.Option{{Code: 15, Data: []byte{0}}},
			wantErr:  "EDE option too short: got 1 bytes, need at least 2",
		},
		{
			name:     "invalid UTF-8 preserves code and other errors",
			response: true,
			options: []dnsmessage.Option{
				{Code: 15, Data: []byte{0, 6, 0xff}},
				{Code: 15, Data: []byte{0, 23}},
			},
			want:    "6 (DNSSEC Bogus); 23 (Network Error)",
			wantErr: "EDE code 6 has invalid UTF-8 extra text",
		},
		{
			name:     "text with controls delimiters and optional null terminator",
			response: true,
			options:  []dnsmessage.Option{{Code: 15, Data: append([]byte{0, 15}, []byte("blocked; \"reason\"\n\x00")...)}},
			want:     `15 (Blocked): "blocked; \"reason\"\n\x00"`,
		},
		{
			name:     "UTF-8 text",
			response: true,
			options:  []dnsmessage.Option{{Code: 15, Data: []byte{0, 15, 0xc3, 0xa9}}},
			want:     "15 (Blocked): \"\u00e9\"",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := dnsmessage.Message{
				Header: dnsmessage.Header{ID: 0x1234, Response: tt.response, RCode: tt.rcode},
				Questions: []dnsmessage.Question{{
					Name:  dnsmessage.MustNewName("example.com."),
					Type:  dnsmessage.TypeA,
					Class: dnsmessage.ClassINET,
				}},
			}
			if tt.options != nil {
				msg.Additionals = []dnsmessage.Resource{
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("example.com."),
							Type:  dnsmessage.TypeA,
							Class: dnsmessage.ClassINET,
						},
						Body: &dnsmessage.AResource{A: [4]byte{192, 0, 2, 1}},
					},
					{
						Header: dnsmessage.ResourceHeader{
							Name:  dnsmessage.MustNewName("."),
							Type:  dnsmessage.TypeOPT,
							Class: 1232,
						},
						Body: &dnsmessage.OPTResource{Options: tt.options},
					},
				}
			}
			wire, err := msg.Pack()
			if err != nil {
				t.Fatal(err)
			}
			var decoded dnsmessage.Message
			if err := decoded.Unpack(wire); err != nil {
				t.Fatal(err)
			}
			got, err := extendedDNSErrors(&decoded)
			if got != tt.want {
				t.Errorf("extendedDNSErrors() = %q, want %q", got, tt.want)
			}
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want %q", err, tt.wantErr)
			}
			if decoded.Header != msg.Header || decoded.Questions[0] != msg.Questions[0] {
				t.Error("EDE decoding changed the DNS header or question")
			}
		})
	}
}
