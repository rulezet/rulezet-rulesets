rule TTP_XOR_MULT_DOSStub_51c8 {
  strings:
    $key_51c8 = { 05 a0 [2] 71 b8 [2] 36 ba [2] 71 ab [2] 3f a7 [2] 33 ad [2] 24 a6 [2] 3f e8 [2] 02 }

  condition:
    any of them
}