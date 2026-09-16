rule TTP_XOR_MULT_DOSStub_23c8 {
  strings:
    $key_23c8 = { 77 a0 [2] 03 b8 [2] 44 ba [2] 03 ab [2] 4d a7 [2] 41 ad [2] 56 a6 [2] 4d e8 [2] 70 }

  condition:
    any of them
}