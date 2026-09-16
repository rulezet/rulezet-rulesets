rule TTP_XOR_MULT_DOSStub_5397 {
  strings:
    $key_5397 = { 07 ff [2] 73 e7 [2] 34 e5 [2] 73 f4 [2] 3d f8 [2] 31 f2 [2] 26 f9 [2] 3d b7 [2] 00 }

  condition:
    any of them
}