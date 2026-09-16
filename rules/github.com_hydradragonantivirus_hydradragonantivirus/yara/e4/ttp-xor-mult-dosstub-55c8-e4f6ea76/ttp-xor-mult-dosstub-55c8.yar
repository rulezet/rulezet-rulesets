rule TTP_XOR_MULT_DOSStub_55c8 {
  strings:
    $key_55c8 = { 01 a0 [2] 75 b8 [2] 32 ba [2] 75 ab [2] 3b a7 [2] 37 ad [2] 20 a6 [2] 3b e8 [2] 06 }

  condition:
    any of them
}