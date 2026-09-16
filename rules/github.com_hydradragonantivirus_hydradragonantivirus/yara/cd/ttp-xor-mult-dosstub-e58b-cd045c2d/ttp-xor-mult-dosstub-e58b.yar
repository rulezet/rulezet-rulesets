rule TTP_XOR_MULT_DOSStub_e58b {
  strings:
    $key_e58b = { b1 e3 [2] c5 fb [2] 82 f9 [2] c5 e8 [2] 8b e4 [2] 87 ee [2] 90 e5 [2] 8b ab [2] b6 }

  condition:
    any of them
}