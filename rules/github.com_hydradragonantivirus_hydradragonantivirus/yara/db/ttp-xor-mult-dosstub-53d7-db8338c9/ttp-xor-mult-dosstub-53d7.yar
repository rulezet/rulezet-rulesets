rule TTP_XOR_MULT_DOSStub_53d7 {
  strings:
    $key_53d7 = { 07 bf [2] 73 a7 [2] 34 a5 [2] 73 b4 [2] 3d b8 [2] 31 b2 [2] 26 b9 [2] 3d f7 [2] 00 }

  condition:
    any of them
}