rule TTP_XOR_MULT_DOSStub_e4c8 {
  strings:
    $key_e4c8 = { b0 a0 [2] c4 b8 [2] 83 ba [2] c4 ab [2] 8a a7 [2] 86 ad [2] 91 a6 [2] 8a e8 [2] b7 }

  condition:
    any of them
}