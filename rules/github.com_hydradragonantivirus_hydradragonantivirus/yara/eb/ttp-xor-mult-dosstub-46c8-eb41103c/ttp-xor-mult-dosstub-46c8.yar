rule TTP_XOR_MULT_DOSStub_46c8 {
  strings:
    $key_46c8 = { 12 a0 [2] 66 b8 [2] 21 ba [2] 66 ab [2] 28 a7 [2] 24 ad [2] 33 a6 [2] 28 e8 [2] 15 }

  condition:
    any of them
}