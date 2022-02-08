// Code generated by protoc-gen-gogo. DO NOT EDIT.
// source: scanner/api/v1/note.proto

package scannerV1

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Note int32

const (
	Note_OS_CVES_UNAVAILABLE             Note = 0
	Note_OS_CVES_STALE                   Note = 1
	Note_LANGUAGE_CVES_UNAVAILABLE       Note = 2
	Note_CERTIFIED_RHEL_SCAN_UNAVAILABLE Note = 3
)

var Note_name = map[int32]string{
	0: "OS_CVES_UNAVAILABLE",
	1: "OS_CVES_STALE",
	2: "LANGUAGE_CVES_UNAVAILABLE",
	3: "CERTIFIED_RHEL_SCAN_UNAVAILABLE",
}

var Note_value = map[string]int32{
	"OS_CVES_UNAVAILABLE":             0,
	"OS_CVES_STALE":                   1,
	"LANGUAGE_CVES_UNAVAILABLE":       2,
	"CERTIFIED_RHEL_SCAN_UNAVAILABLE": 3,
}

func (x Note) String() string {
	return proto.EnumName(Note_name, int32(x))
}

func (Note) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_f62057ab5009588b, []int{0}
}

func init() {
	proto.RegisterEnum("scannerV1.Note", Note_name, Note_value)
}

func init() { proto.RegisterFile("scanner/api/v1/note.proto", fileDescriptor_f62057ab5009588b) }

var fileDescriptor_f62057ab5009588b = []byte{
	// 197 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x92, 0x2c, 0x4e, 0x4e, 0xcc,
	0xcb, 0x4b, 0x2d, 0xd2, 0x4f, 0x2c, 0xc8, 0xd4, 0x2f, 0x33, 0xd4, 0xcf, 0xcb, 0x2f, 0x49, 0xd5,
	0x2b, 0x28, 0xca, 0x2f, 0xc9, 0x17, 0xe2, 0x84, 0x4a, 0x85, 0x19, 0x6a, 0x95, 0x71, 0xb1, 0xf8,
	0xe5, 0x97, 0xa4, 0x0a, 0x89, 0x73, 0x09, 0xfb, 0x07, 0xc7, 0x3b, 0x87, 0xb9, 0x06, 0xc7, 0x87,
	0xfa, 0x39, 0x86, 0x39, 0x7a, 0xfa, 0x38, 0x3a, 0xf9, 0xb8, 0x0a, 0x30, 0x08, 0x09, 0x72, 0xf1,
	0xc2, 0x24, 0x82, 0x43, 0x1c, 0x7d, 0x5c, 0x05, 0x18, 0x85, 0x64, 0xb9, 0x24, 0x7d, 0x1c, 0xfd,
	0xdc, 0x43, 0x1d, 0xdd, 0x5d, 0x31, 0x75, 0x30, 0x09, 0x29, 0x73, 0xc9, 0x3b, 0xbb, 0x06, 0x85,
	0x78, 0xba, 0x79, 0xba, 0xba, 0xc4, 0x07, 0x79, 0xb8, 0xfa, 0xc4, 0x07, 0x3b, 0x3b, 0xfa, 0xa1,
	0x28, 0x62, 0x76, 0xb2, 0x3d, 0xf1, 0x48, 0x8e, 0xf1, 0xc2, 0x23, 0x39, 0xc6, 0x07, 0x8f, 0xe4,
	0x18, 0x67, 0x3c, 0x96, 0x63, 0xe0, 0x52, 0xc8, 0xcc, 0xd7, 0x2b, 0x2e, 0x49, 0x4c, 0xce, 0x2e,
	0xca, 0xaf, 0x80, 0xb8, 0x53, 0x2f, 0xb1, 0x20, 0x53, 0x0f, 0xea, 0x54, 0xbd, 0x32, 0xc3, 0x28,
	0x84, 0xb3, 0x93, 0xd8, 0xc0, 0x0a, 0x8c, 0x01, 0x01, 0x00, 0x00, 0xff, 0xff, 0xd3, 0xb4, 0xdb,
	0xf8, 0xe5, 0x00, 0x00, 0x00,
}