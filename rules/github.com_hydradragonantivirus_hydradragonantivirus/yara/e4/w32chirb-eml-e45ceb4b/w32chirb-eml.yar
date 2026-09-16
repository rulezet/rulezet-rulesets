rule W32ChirB_eml {
   meta:
      description = "readme.eml - Chir.B"
      author = "wit0k"
      reference = ""
      date = "2018-08-30"
      hash1 = "d41a5c4fe5171cbfe26ef04da347188d1c22e34d2d4cdffd833f38d61e3b6ec8"
   strings:
      $s4 = "<html><HEAD></HEAD><body bgColor=3D#ffffff><iframe src=3Dcid:THE-CID height=3D0 width=3D0></iframe></body></html>" fullword ascii
      $s6 = "UAToCwAAAGCJGIlQBPzzpGHP+maPAGaPQAaLdQiLfQyLTRDM+2HJwgwA6cgAAABgi0UIagBQUGoA/5aQAAAAYcnCBAAAAAAAAAAAAMMAAAAAAAAAAAAAAAAAAAA=" fullword ascii
      $s7 = /FROM: .{1,20}@yahoo\.com/ fullword ascii nocase
      $s8 = /Content-Type: audio\/x-wav; name=.{1,20}.exe/ fullword ascii nocase
      $s11 = "dmFTY3JpcHQiPndpbmRvdy5vcGVuKCJyZWFkbWUuZW1sIiwgbnVsbCwicmVzaXphYmxlPW5vLHRvcD02MDAwLGxlZnQ9NjAwMCIpPC9zY3JpcHQ+PC9odG1sPgBYanhQ" ascii 
      $s18 = "TVpQAAIAAAAEAA8A//8AALgAAAAAAAAAQAAaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAALoQAA4ftAnNIbgBTM0hkJBUaGlzIHByb2dyYW0gbXVz" ascii 
   condition:
      ( uint16(0) == 0x20ce and filesize < 120KB and ( 3 of them )
      ) or ( all of them )
}