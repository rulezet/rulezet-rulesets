rule TTP_XOR_MULT_DOSStub_67c8 {
  strings:
    $key_67c8 = { 33 a0 [2] 47 b8 [2] 00 ba [2] 47 ab [2] 09 a7 [2] 05 ad [2] 12 a6 [2] 09 e8 [2] 34 }

  condition:
    any of them
}