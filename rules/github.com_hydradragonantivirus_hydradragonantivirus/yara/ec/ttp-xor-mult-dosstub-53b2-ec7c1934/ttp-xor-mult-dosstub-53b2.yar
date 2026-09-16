rule TTP_XOR_MULT_DOSStub_53b2 {
  strings:
    $key_53b2 = { 07 da [2] 73 c2 [2] 34 c0 [2] 73 d1 [2] 3d dd [2] 31 d7 [2] 26 dc [2] 3d 92 [2] 00 }

  condition:
    any of them
}