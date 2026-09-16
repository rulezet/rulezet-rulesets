rule TTP_XOR_MULT_DOSStub_41c8 {
  strings:
    $key_41c8 = { 15 a0 [2] 61 b8 [2] 26 ba [2] 61 ab [2] 2f a7 [2] 23 ad [2] 34 a6 [2] 2f e8 [2] 12 }

  condition:
    any of them
}