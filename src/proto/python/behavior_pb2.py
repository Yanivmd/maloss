# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: behavior.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf.internal import enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()


import info_pb2 as info__pb2
import module_pb2 as module__pb2


DESCRIPTOR = _descriptor.FileDescriptor(
  name='behavior.proto',
  package='proto',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n\x0e\x62\x65havior.proto\x12\x05proto\x1a\ninfo.proto\x1a\x0cmodule.proto\"\xc2\x01\n\x0fNetworkActivity\x12\x0e\n\x06\x64omain\x18\x01 \x01(\t\x12\x0b\n\x03url\x18\x02 \x01(\t\x12\n\n\x02ip\x18\x03 \x01(\t\x12\x0c\n\x04port\x18\x04 \x01(\x05\x12\x10\n\x08protocol\x18\x05 \x01(\t\x12\x14\n\x0csend_content\x18\x06 \x01(\t\x12\x19\n\x11send_content_size\x18\x07 \x01(\x05\x12\x17\n\x0freceive_content\x18\x08 \x01(\t\x12\x1c\n\x14receive_content_size\x18\t \x01(\x05\"\x9e\x02\n\x0c\x46ileActivity\x12\x10\n\x08\x66ilename\x18\x01 \x01(\t\x12\x10\n\x08\x66ilepath\x18\x02 \x01(\t\x12\x0c\n\x04mode\x18\x03 \x01(\t\x12\x12\n\npermission\x18\x04 \x01(\t\x12\x14\n\x0cread_content\x18\x05 \x01(\t\x12\x19\n\x11read_content_size\x18\x06 \x01(\t\x12\x13\n\x0b\x61\x64\x64_content\x18\x07 \x01(\t\x12\x18\n\x10\x61\x64\x64_content_size\x18\x08 \x01(\x05\x12\x16\n\x0eremove_content\x18\t \x01(\t\x12\x1b\n\x13remove_content_size\x18\n \x01(\x05\x12\x16\n\x0emodify_content\x18\x0b \x01(\t\x12\x1b\n\x13modify_content_size\x18\x0c \x01(\x05\"\x87\x01\n\x12SensitivenActivity\x12\x0b\n\x03pid\x18\x01 \x01(\t\x12\x0f\n\x07\x63mdline\x18\x02 \x01(\t\x12\x0b\n\x03\x65xe\x18\x03 \x01(\t\x12\x0b\n\x03\x63wd\x18\x04 \x01(\t\x12\x0c\n\x04root\x18\x05 \x01(\t\x12\x0c\n\x04ppid\x18\x06 \x01(\t\x12\x0c\n\x04user\x18\x07 \x01(\t\x12\x0f\n\x07syscall\x18\x08 \x01(\t\"\xf2\x02\n\x0fProcessActivity\x12\x0b\n\x03pid\x18\x01 \x01(\t\x12\x0f\n\x07\x63mdline\x18\x02 \x01(\t\x12\x0b\n\x03\x65xe\x18\x03 \x01(\t\x12\x0b\n\x03\x63wd\x18\x04 \x01(\t\x12\x0c\n\x04root\x18\x05 \x01(\t\x12\x0c\n\x04ppid\x18\x06 \x01(\t\x12\x0c\n\x04user\x18\x07 \x01(\t\x12\x12\n\npermission\x18\x08 \x01(\t\x12\x14\n\x0cmain_process\x18\t \x01(\x08\x12\x32\n\x12network_activities\x18\n \x03(\x0b\x32\x16.proto.NetworkActivity\x12,\n\x0f\x66ile_activities\x18\x0b \x03(\x0b\x32\x13.proto.FileActivity\x12\x38\n\x18\x63hild_process_activities\x18\x0c \x03(\x0b\x32\x16.proto.ProcessActivity\x12\x37\n\x14sensitive_activities\x18\r \x03(\x0b\x32\x19.proto.SensitivenActivity\"\xd3\x01\n\x0f\x44ynamicAnalysis\x12*\n\ranalysis_type\x18\x01 \x01(\x0e\x32\x13.proto.AnalysisType\x12&\n\x08\x65xe_type\x18\x02 \x01(\x0e\x32\x14.proto.ExecutionType\x12\x10\n\x08\x65xe_user\x18\x03 \x01(\t\x12\x11\n\ttimestamp\x18\x04 \x01(\t\x12\x15\n\rend_timestamp\x18\x05 \x01(\t\x12\x30\n\x10process_activity\x18\x06 \x01(\x0b\x32\x16.proto.ProcessActivity\"{\n\x0eStaticAnalysis\x12*\n\ranalysis_type\x18\x01 \x01(\x0e\x32\x13.proto.AnalysisType\x12\x11\n\ttimestamp\x18\x02 \x01(\t\x12*\n\rcode_activity\x18\x03 \x01(\x0b\x32\x13.proto.ModuleStatic\"\xd4\x01\n\x10\x43oncolicAnalysis\x12*\n\ranalysis_type\x18\x01 \x01(\x0e\x32\x13.proto.AnalysisType\x12&\n\x08\x65xe_type\x18\x02 \x01(\x0e\x32\x14.proto.ExecutionType\x12\x10\n\x08\x65xe_user\x18\x03 \x01(\t\x12\x11\n\ttimestamp\x18\x04 \x01(\t\x12\x15\n\rend_timestamp\x18\x05 \x01(\t\x12\x30\n\x10process_activity\x18\x06 \x01(\x0b\x32\x16.proto.ProcessActivity\"\xcd\x01\n\x0e\x41nalysisResult\x12(\n\x0cpackage_info\x18\x01 \x01(\x0b\x32\x12.proto.PackageInfo\x12/\n\x0f\x64ynamic_results\x18\x02 \x03(\x0b\x32\x16.proto.DynamicAnalysis\x12-\n\x0estatic_results\x18\x03 \x03(\x0b\x32\x15.proto.StaticAnalysis\x12\x31\n\x10\x63oncolic_results\x18\x04 \x03(\x0b\x32\x17.proto.ConcolicAnalysis*>\n\rExecutionType\x12\x0b\n\x07INSTALL\x10\x00\x12\x08\n\x04MAIN\x10\x01\x12\x0c\n\x08\x45XERCISE\x10\x02\x12\x08\n\x04TEST\x10\x03*Q\n\x0c\x41nalysisType\x12\r\n\tAPI_USAGE\x10\x00\x12\x10\n\x0cREACHABILITY\x10\x01\x12\x12\n\x0eTAINT_TRACKING\x10\x02\x12\x0c\n\x08SYMBOLIC\x10\x03\x62\x06proto3')
  ,
  dependencies=[info__pb2.DESCRIPTOR,module__pb2.DESCRIPTOR,])

_EXECUTIONTYPE = _descriptor.EnumDescriptor(
  name='ExecutionType',
  full_name='proto.ExecutionType',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='INSTALL', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='MAIN', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='EXERCISE', index=2, number=2,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='TEST', index=3, number=3,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=1810,
  serialized_end=1872,
)
_sym_db.RegisterEnumDescriptor(_EXECUTIONTYPE)

ExecutionType = enum_type_wrapper.EnumTypeWrapper(_EXECUTIONTYPE)
_ANALYSISTYPE = _descriptor.EnumDescriptor(
  name='AnalysisType',
  full_name='proto.AnalysisType',
  filename=None,
  file=DESCRIPTOR,
  values=[
    _descriptor.EnumValueDescriptor(
      name='API_USAGE', index=0, number=0,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='REACHABILITY', index=1, number=1,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='TAINT_TRACKING', index=2, number=2,
      serialized_options=None,
      type=None),
    _descriptor.EnumValueDescriptor(
      name='SYMBOLIC', index=3, number=3,
      serialized_options=None,
      type=None),
  ],
  containing_type=None,
  serialized_options=None,
  serialized_start=1874,
  serialized_end=1955,
)
_sym_db.RegisterEnumDescriptor(_ANALYSISTYPE)

AnalysisType = enum_type_wrapper.EnumTypeWrapper(_ANALYSISTYPE)
INSTALL = 0
MAIN = 1
EXERCISE = 2
TEST = 3
API_USAGE = 0
REACHABILITY = 1
TAINT_TRACKING = 2
SYMBOLIC = 3



_NETWORKACTIVITY = _descriptor.Descriptor(
  name='NetworkActivity',
  full_name='proto.NetworkActivity',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='domain', full_name='proto.NetworkActivity.domain', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='url', full_name='proto.NetworkActivity.url', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ip', full_name='proto.NetworkActivity.ip', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='port', full_name='proto.NetworkActivity.port', index=3,
      number=4, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='protocol', full_name='proto.NetworkActivity.protocol', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='send_content', full_name='proto.NetworkActivity.send_content', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='send_content_size', full_name='proto.NetworkActivity.send_content_size', index=6,
      number=7, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='receive_content', full_name='proto.NetworkActivity.receive_content', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='receive_content_size', full_name='proto.NetworkActivity.receive_content_size', index=8,
      number=9, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=52,
  serialized_end=246,
)


_FILEACTIVITY = _descriptor.Descriptor(
  name='FileActivity',
  full_name='proto.FileActivity',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='filename', full_name='proto.FileActivity.filename', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='filepath', full_name='proto.FileActivity.filepath', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='mode', full_name='proto.FileActivity.mode', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='permission', full_name='proto.FileActivity.permission', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='read_content', full_name='proto.FileActivity.read_content', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='read_content_size', full_name='proto.FileActivity.read_content_size', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='add_content', full_name='proto.FileActivity.add_content', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='add_content_size', full_name='proto.FileActivity.add_content_size', index=7,
      number=8, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='remove_content', full_name='proto.FileActivity.remove_content', index=8,
      number=9, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='remove_content_size', full_name='proto.FileActivity.remove_content_size', index=9,
      number=10, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='modify_content', full_name='proto.FileActivity.modify_content', index=10,
      number=11, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='modify_content_size', full_name='proto.FileActivity.modify_content_size', index=11,
      number=12, type=5, cpp_type=1, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=249,
  serialized_end=535,
)


_SENSITIVENACTIVITY = _descriptor.Descriptor(
  name='SensitivenActivity',
  full_name='proto.SensitivenActivity',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='pid', full_name='proto.SensitivenActivity.pid', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='cmdline', full_name='proto.SensitivenActivity.cmdline', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='exe', full_name='proto.SensitivenActivity.exe', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='cwd', full_name='proto.SensitivenActivity.cwd', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='root', full_name='proto.SensitivenActivity.root', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ppid', full_name='proto.SensitivenActivity.ppid', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='user', full_name='proto.SensitivenActivity.user', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='syscall', full_name='proto.SensitivenActivity.syscall', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=538,
  serialized_end=673,
)


_PROCESSACTIVITY = _descriptor.Descriptor(
  name='ProcessActivity',
  full_name='proto.ProcessActivity',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='pid', full_name='proto.ProcessActivity.pid', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='cmdline', full_name='proto.ProcessActivity.cmdline', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='exe', full_name='proto.ProcessActivity.exe', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='cwd', full_name='proto.ProcessActivity.cwd', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='root', full_name='proto.ProcessActivity.root', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='ppid', full_name='proto.ProcessActivity.ppid', index=5,
      number=6, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='user', full_name='proto.ProcessActivity.user', index=6,
      number=7, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='permission', full_name='proto.ProcessActivity.permission', index=7,
      number=8, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='main_process', full_name='proto.ProcessActivity.main_process', index=8,
      number=9, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='network_activities', full_name='proto.ProcessActivity.network_activities', index=9,
      number=10, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='file_activities', full_name='proto.ProcessActivity.file_activities', index=10,
      number=11, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='child_process_activities', full_name='proto.ProcessActivity.child_process_activities', index=11,
      number=12, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='sensitive_activities', full_name='proto.ProcessActivity.sensitive_activities', index=12,
      number=13, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=676,
  serialized_end=1046,
)


_DYNAMICANALYSIS = _descriptor.Descriptor(
  name='DynamicAnalysis',
  full_name='proto.DynamicAnalysis',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='analysis_type', full_name='proto.DynamicAnalysis.analysis_type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='exe_type', full_name='proto.DynamicAnalysis.exe_type', index=1,
      number=2, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='exe_user', full_name='proto.DynamicAnalysis.exe_user', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='timestamp', full_name='proto.DynamicAnalysis.timestamp', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='end_timestamp', full_name='proto.DynamicAnalysis.end_timestamp', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='process_activity', full_name='proto.DynamicAnalysis.process_activity', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1049,
  serialized_end=1260,
)


_STATICANALYSIS = _descriptor.Descriptor(
  name='StaticAnalysis',
  full_name='proto.StaticAnalysis',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='analysis_type', full_name='proto.StaticAnalysis.analysis_type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='timestamp', full_name='proto.StaticAnalysis.timestamp', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='code_activity', full_name='proto.StaticAnalysis.code_activity', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1262,
  serialized_end=1385,
)


_CONCOLICANALYSIS = _descriptor.Descriptor(
  name='ConcolicAnalysis',
  full_name='proto.ConcolicAnalysis',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='analysis_type', full_name='proto.ConcolicAnalysis.analysis_type', index=0,
      number=1, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='exe_type', full_name='proto.ConcolicAnalysis.exe_type', index=1,
      number=2, type=14, cpp_type=8, label=1,
      has_default_value=False, default_value=0,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='exe_user', full_name='proto.ConcolicAnalysis.exe_user', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='timestamp', full_name='proto.ConcolicAnalysis.timestamp', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='end_timestamp', full_name='proto.ConcolicAnalysis.end_timestamp', index=4,
      number=5, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='process_activity', full_name='proto.ConcolicAnalysis.process_activity', index=5,
      number=6, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1388,
  serialized_end=1600,
)


_ANALYSISRESULT = _descriptor.Descriptor(
  name='AnalysisResult',
  full_name='proto.AnalysisResult',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='package_info', full_name='proto.AnalysisResult.package_info', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='dynamic_results', full_name='proto.AnalysisResult.dynamic_results', index=1,
      number=2, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='static_results', full_name='proto.AnalysisResult.static_results', index=2,
      number=3, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='concolic_results', full_name='proto.AnalysisResult.concolic_results', index=3,
      number=4, type=11, cpp_type=10, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=1603,
  serialized_end=1808,
)

_PROCESSACTIVITY.fields_by_name['network_activities'].message_type = _NETWORKACTIVITY
_PROCESSACTIVITY.fields_by_name['file_activities'].message_type = _FILEACTIVITY
_PROCESSACTIVITY.fields_by_name['child_process_activities'].message_type = _PROCESSACTIVITY
_PROCESSACTIVITY.fields_by_name['sensitive_activities'].message_type = _SENSITIVENACTIVITY
_DYNAMICANALYSIS.fields_by_name['analysis_type'].enum_type = _ANALYSISTYPE
_DYNAMICANALYSIS.fields_by_name['exe_type'].enum_type = _EXECUTIONTYPE
_DYNAMICANALYSIS.fields_by_name['process_activity'].message_type = _PROCESSACTIVITY
_STATICANALYSIS.fields_by_name['analysis_type'].enum_type = _ANALYSISTYPE
_STATICANALYSIS.fields_by_name['code_activity'].message_type = module__pb2._MODULESTATIC
_CONCOLICANALYSIS.fields_by_name['analysis_type'].enum_type = _ANALYSISTYPE
_CONCOLICANALYSIS.fields_by_name['exe_type'].enum_type = _EXECUTIONTYPE
_CONCOLICANALYSIS.fields_by_name['process_activity'].message_type = _PROCESSACTIVITY
_ANALYSISRESULT.fields_by_name['package_info'].message_type = info__pb2._PACKAGEINFO
_ANALYSISRESULT.fields_by_name['dynamic_results'].message_type = _DYNAMICANALYSIS
_ANALYSISRESULT.fields_by_name['static_results'].message_type = _STATICANALYSIS
_ANALYSISRESULT.fields_by_name['concolic_results'].message_type = _CONCOLICANALYSIS
DESCRIPTOR.message_types_by_name['NetworkActivity'] = _NETWORKACTIVITY
DESCRIPTOR.message_types_by_name['FileActivity'] = _FILEACTIVITY
DESCRIPTOR.message_types_by_name['SensitivenActivity'] = _SENSITIVENACTIVITY
DESCRIPTOR.message_types_by_name['ProcessActivity'] = _PROCESSACTIVITY
DESCRIPTOR.message_types_by_name['DynamicAnalysis'] = _DYNAMICANALYSIS
DESCRIPTOR.message_types_by_name['StaticAnalysis'] = _STATICANALYSIS
DESCRIPTOR.message_types_by_name['ConcolicAnalysis'] = _CONCOLICANALYSIS
DESCRIPTOR.message_types_by_name['AnalysisResult'] = _ANALYSISRESULT
DESCRIPTOR.enum_types_by_name['ExecutionType'] = _EXECUTIONTYPE
DESCRIPTOR.enum_types_by_name['AnalysisType'] = _ANALYSISTYPE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

NetworkActivity = _reflection.GeneratedProtocolMessageType('NetworkActivity', (_message.Message,), dict(
  DESCRIPTOR = _NETWORKACTIVITY,
  __module__ = 'behavior_pb2'
  # @@protoc_insertion_point(class_scope:proto.NetworkActivity)
  ))
_sym_db.RegisterMessage(NetworkActivity)

FileActivity = _reflection.GeneratedProtocolMessageType('FileActivity', (_message.Message,), dict(
  DESCRIPTOR = _FILEACTIVITY,
  __module__ = 'behavior_pb2'
  # @@protoc_insertion_point(class_scope:proto.FileActivity)
  ))
_sym_db.RegisterMessage(FileActivity)

SensitivenActivity = _reflection.GeneratedProtocolMessageType('SensitivenActivity', (_message.Message,), dict(
  DESCRIPTOR = _SENSITIVENACTIVITY,
  __module__ = 'behavior_pb2'
  # @@protoc_insertion_point(class_scope:proto.SensitivenActivity)
  ))
_sym_db.RegisterMessage(SensitivenActivity)

ProcessActivity = _reflection.GeneratedProtocolMessageType('ProcessActivity', (_message.Message,), dict(
  DESCRIPTOR = _PROCESSACTIVITY,
  __module__ = 'behavior_pb2'
  # @@protoc_insertion_point(class_scope:proto.ProcessActivity)
  ))
_sym_db.RegisterMessage(ProcessActivity)

DynamicAnalysis = _reflection.GeneratedProtocolMessageType('DynamicAnalysis', (_message.Message,), dict(
  DESCRIPTOR = _DYNAMICANALYSIS,
  __module__ = 'behavior_pb2'
  # @@protoc_insertion_point(class_scope:proto.DynamicAnalysis)
  ))
_sym_db.RegisterMessage(DynamicAnalysis)

StaticAnalysis = _reflection.GeneratedProtocolMessageType('StaticAnalysis', (_message.Message,), dict(
  DESCRIPTOR = _STATICANALYSIS,
  __module__ = 'behavior_pb2'
  # @@protoc_insertion_point(class_scope:proto.StaticAnalysis)
  ))
_sym_db.RegisterMessage(StaticAnalysis)

ConcolicAnalysis = _reflection.GeneratedProtocolMessageType('ConcolicAnalysis', (_message.Message,), dict(
  DESCRIPTOR = _CONCOLICANALYSIS,
  __module__ = 'behavior_pb2'
  # @@protoc_insertion_point(class_scope:proto.ConcolicAnalysis)
  ))
_sym_db.RegisterMessage(ConcolicAnalysis)

AnalysisResult = _reflection.GeneratedProtocolMessageType('AnalysisResult', (_message.Message,), dict(
  DESCRIPTOR = _ANALYSISRESULT,
  __module__ = 'behavior_pb2'
  # @@protoc_insertion_point(class_scope:proto.AnalysisResult)
  ))
_sym_db.RegisterMessage(AnalysisResult)


# @@protoc_insertion_point(module_scope)
