rule INFO_MacOS_NamedPipe_ObjC_XPC_API {
  meta:
    author      = "Greg Lesnewich"
    date        = "2023-01-28"
    version     = "1.0"
    description = "check for references to XPC, MacOS low-level interprocess communications, via the XPC APIs"

  strings:
    $ = "IOSurfaceLookupFromXPCObject" ascii wide
    $ = "IOSurfaceCreateXPCObject" ascii wide

  condition:
    any of them
}