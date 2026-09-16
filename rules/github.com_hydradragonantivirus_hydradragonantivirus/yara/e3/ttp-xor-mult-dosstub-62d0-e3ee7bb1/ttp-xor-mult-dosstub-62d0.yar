rule TTP_XOR_MULT_DOSStub_62d0 {
  strings:
    $key_62d0 = { 36 b8 [2] 42 a0 [2] 05 a2 [2] 42 b3 [2] 0c bf [2] 00 b5 [2] 17 be [2] 0c f0 [2] 31 }

  condition:
    any of them
}