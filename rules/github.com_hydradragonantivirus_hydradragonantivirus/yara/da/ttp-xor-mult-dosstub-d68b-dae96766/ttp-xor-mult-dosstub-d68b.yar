rule TTP_XOR_MULT_DOSStub_d68b {
  strings:
    $key_d68b = { 82 e3 [2] f6 fb [2] b1 f9 [2] f6 e8 [2] b8 e4 [2] b4 ee [2] a3 e5 [2] b8 ab [2] 85 }

  condition:
    any of them
}