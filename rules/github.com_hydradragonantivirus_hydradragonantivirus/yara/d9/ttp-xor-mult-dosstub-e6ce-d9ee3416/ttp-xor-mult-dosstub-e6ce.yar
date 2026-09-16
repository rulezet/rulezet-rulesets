rule TTP_XOR_MULT_DOSStub_e6ce {
  strings:
    $key_e6ce = { b2 a6 [2] c6 be [2] 81 bc [2] c6 ad [2] 88 a1 [2] 84 ab [2] 93 a0 [2] 88 ee [2] b5 }

  condition:
    any of them
}