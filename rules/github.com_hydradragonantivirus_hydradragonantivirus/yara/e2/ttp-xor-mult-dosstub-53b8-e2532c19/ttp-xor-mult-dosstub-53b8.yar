rule TTP_XOR_MULT_DOSStub_53b8 {
  strings:
    $key_53b8 = { 07 d0 [2] 73 c8 [2] 34 ca [2] 73 db [2] 3d d7 [2] 31 dd [2] 26 d6 [2] 3d 98 [2] 00 }

  condition:
    any of them
}