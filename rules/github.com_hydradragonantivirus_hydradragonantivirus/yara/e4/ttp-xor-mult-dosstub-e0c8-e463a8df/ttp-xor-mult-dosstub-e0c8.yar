rule TTP_XOR_MULT_DOSStub_e0c8 {
  strings:
    $key_e0c8 = { b4 a0 [2] c0 b8 [2] 87 ba [2] c0 ab [2] 8e a7 [2] 82 ad [2] 95 a6 [2] 8e e8 [2] b3 }

  condition:
    any of them
}