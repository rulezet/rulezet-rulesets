rule TTP_XOR_MULT_DOSStub_d6ce {
  strings:
    $key_d6ce = { 82 a6 [2] f6 be [2] b1 bc [2] f6 ad [2] b8 a1 [2] b4 ab [2] a3 a0 [2] b8 ee [2] 85 }

  condition:
    any of them
}