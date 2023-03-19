// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.27.1
// 	protoc        v3.14.0
// source: protob/shared.proto

package common

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type ECPoint struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	X []byte `protobuf:"bytes,1,opt,name=x,proto3" json:"x,omitempty"`
	Y []byte `protobuf:"bytes,2,opt,name=y,proto3" json:"y,omitempty"`
}

func (x *ECPoint) Reset() {
	*x = ECPoint{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_shared_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ECPoint) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ECPoint) ProtoMessage() {}

func (x *ECPoint) ProtoReflect() protoreflect.Message {
	mi := &file_protob_shared_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ECPoint.ProtoReflect.Descriptor instead.
func (*ECPoint) Descriptor() ([]byte, []int) {
	return file_protob_shared_proto_rawDescGZIP(), []int{0}
}

func (x *ECPoint) GetX() []byte {
	if x != nil {
		return x.X
	}
	return nil
}

func (x *ECPoint) GetY() []byte {
	if x != nil {
		return x.Y
	}
	return nil
}

type ECSignature struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Signature []byte `protobuf:"bytes,1,opt,name=signature,proto3" json:"signature,omitempty"`
	// Ethereum-style Recovery ID: Used to enable extracting the public key from the signature.
	SignatureRecovery []byte `protobuf:"bytes,2,opt,name=signature_recovery,json=signatureRecovery,proto3" json:"signature_recovery,omitempty"`
	// Signature components R, S
	R []byte `protobuf:"bytes,3,opt,name=r,proto3" json:"r,omitempty"`
	S []byte `protobuf:"bytes,4,opt,name=s,proto3" json:"s,omitempty"`
	// M represents the original message digest that was signed M
	M []byte `protobuf:"bytes,5,opt,name=m,proto3" json:"m,omitempty"`
}

func (x *ECSignature) Reset() {
	*x = ECSignature{}
	if protoimpl.UnsafeEnabled {
		mi := &file_protob_shared_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ECSignature) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ECSignature) ProtoMessage() {}

func (x *ECSignature) ProtoReflect() protoreflect.Message {
	mi := &file_protob_shared_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ECSignature.ProtoReflect.Descriptor instead.
func (*ECSignature) Descriptor() ([]byte, []int) {
	return file_protob_shared_proto_rawDescGZIP(), []int{1}
}

func (x *ECSignature) GetSignature() []byte {
	if x != nil {
		return x.Signature
	}
	return nil
}

func (x *ECSignature) GetSignatureRecovery() []byte {
	if x != nil {
		return x.SignatureRecovery
	}
	return nil
}

func (x *ECSignature) GetR() []byte {
	if x != nil {
		return x.R
	}
	return nil
}

func (x *ECSignature) GetS() []byte {
	if x != nil {
		return x.S
	}
	return nil
}

func (x *ECSignature) GetM() []byte {
	if x != nil {
		return x.M
	}
	return nil
}

var File_protob_shared_proto protoreflect.FileDescriptor

var file_protob_shared_proto_rawDesc = []byte{
	0x0a, 0x13, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x2f, 0x73, 0x68, 0x61, 0x72, 0x65, 0x64, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x25, 0x0a, 0x07, 0x45, 0x43, 0x50, 0x6f, 0x69, 0x6e, 0x74,
	0x12, 0x0c, 0x0a, 0x01, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x78, 0x12, 0x0c,
	0x0a, 0x01, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x79, 0x22, 0x84, 0x01, 0x0a,
	0x0b, 0x45, 0x43, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x1c, 0x0a, 0x09,
	0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0c, 0x52,
	0x09, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x12, 0x2d, 0x0a, 0x12, 0x73, 0x69,
	0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65, 0x5f, 0x72, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79,
	0x18, 0x02, 0x20, 0x01, 0x28, 0x0c, 0x52, 0x11, 0x73, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72,
	0x65, 0x52, 0x65, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x12, 0x0c, 0x0a, 0x01, 0x72, 0x18, 0x03,
	0x20, 0x01, 0x28, 0x0c, 0x52, 0x01, 0x72, 0x12, 0x0c, 0x0a, 0x01, 0x73, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x0c, 0x52, 0x01, 0x73, 0x12, 0x0c, 0x0a, 0x01, 0x6d, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0c,
	0x52, 0x01, 0x6d, 0x42, 0x28, 0x5a, 0x26, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f,
	0x6d, 0x2f, 0x73, 0x69, 0x73, 0x75, 0x2d, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x74,
	0x73, 0x73, 0x2d, 0x6c, 0x69, 0x62, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_protob_shared_proto_rawDescOnce sync.Once
	file_protob_shared_proto_rawDescData = file_protob_shared_proto_rawDesc
)

func file_protob_shared_proto_rawDescGZIP() []byte {
	file_protob_shared_proto_rawDescOnce.Do(func() {
		file_protob_shared_proto_rawDescData = protoimpl.X.CompressGZIP(file_protob_shared_proto_rawDescData)
	})
	return file_protob_shared_proto_rawDescData
}

var file_protob_shared_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_protob_shared_proto_goTypes = []interface{}{
	(*ECPoint)(nil),     // 0: ECPoint
	(*ECSignature)(nil), // 1: ECSignature
}
var file_protob_shared_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_protob_shared_proto_init() }
func file_protob_shared_proto_init() {
	if File_protob_shared_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_protob_shared_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ECPoint); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_protob_shared_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ECSignature); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_protob_shared_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_protob_shared_proto_goTypes,
		DependencyIndexes: file_protob_shared_proto_depIdxs,
		MessageInfos:      file_protob_shared_proto_msgTypes,
	}.Build()
	File_protob_shared_proto = out.File
	file_protob_shared_proto_rawDesc = nil
	file_protob_shared_proto_goTypes = nil
	file_protob_shared_proto_depIdxs = nil
}
