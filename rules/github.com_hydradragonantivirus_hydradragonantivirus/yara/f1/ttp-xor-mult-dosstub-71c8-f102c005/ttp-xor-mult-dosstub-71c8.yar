rule TTP_XOR_MULT_DOSStub_71c8 {
  strings:
    $key_71c8 = { 25 a0 [2] 51 b8 [2] 16 ba [2] 51 ab [2] 1f a7 [2] 13 ad [2] 04 a6 [2] 1f e8 [2] 22 }

  condition:
    any of them
}