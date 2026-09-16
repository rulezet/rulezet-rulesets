rule M_APT_VIRTUALPITA_1 {
   meta:
      author = "Mandiant"
      md5 = "fe34b7c071d96dac498b72a4a07cb246"
      description = "Finds opcodes to set a port to bind on 2233, encompassing the setsockopt(), htons(), and bind() from 40973d to 409791 in fe34b7c071d96dac498b72a4a07cb246 (may produce some FPs - comment by Florian Roth)"
      modified = "2023-11-25"
      score = 60        id = "bdfbe29a-f7db-50d9-a909-d4ca96cc0731"
   strings:
      $x = { 8b ?? ?? 4? b8 04 00 00 00 [0-4] ba 02 00 00 00 be 01 00 00 00 [0-2] e8 ?? ?? ?? ?? 89 4? ?? 83 7? ?? 00 79 [0-50] ba 10 00 00 00 [0-10] e8 }
   condition:
      uint32(0) == 0x464c457f and all of them
}