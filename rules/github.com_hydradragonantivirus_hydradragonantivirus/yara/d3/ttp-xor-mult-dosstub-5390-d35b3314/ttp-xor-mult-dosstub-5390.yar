rule TTP_XOR_MULT_DOSStub_5390 {
  strings:
    $key_5390 = { 07 f8 [2] 73 e0 [2] 34 e2 [2] 73 f3 [2] 3d ff [2] 31 f5 [2] 26 fe [2] 3d b0 [2] 00 }

  condition:
    any of them
}