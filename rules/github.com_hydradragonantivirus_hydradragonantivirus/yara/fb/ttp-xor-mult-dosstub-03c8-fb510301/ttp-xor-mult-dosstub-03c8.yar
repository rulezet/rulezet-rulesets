rule TTP_XOR_MULT_DOSStub_03c8 {
  strings:
    $key_03c8 = { 57 a0 [2] 23 b8 [2] 64 ba [2] 23 ab [2] 6d a7 [2] 61 ad [2] 76 a6 [2] 6d e8 [2] 50 }

  condition:
    any of them
}