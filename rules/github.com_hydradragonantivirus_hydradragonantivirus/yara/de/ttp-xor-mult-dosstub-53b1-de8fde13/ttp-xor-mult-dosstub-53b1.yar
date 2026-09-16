rule TTP_XOR_MULT_DOSStub_53b1 {
  strings:
    $key_53b1 = { 07 d9 [2] 73 c1 [2] 34 c3 [2] 73 d2 [2] 3d de [2] 31 d4 [2] 26 df [2] 3d 91 [2] 00 }

  condition:
    any of them
}