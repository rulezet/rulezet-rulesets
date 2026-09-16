rule TTP_XOR_MULT_DOSStub_53b9 {
  strings:
    $key_53b9 = { 07 d1 [2] 73 c9 [2] 34 cb [2] 73 da [2] 3d d6 [2] 31 dc [2] 26 d7 [2] 3d 99 [2] 00 }

  condition:
    any of them
}