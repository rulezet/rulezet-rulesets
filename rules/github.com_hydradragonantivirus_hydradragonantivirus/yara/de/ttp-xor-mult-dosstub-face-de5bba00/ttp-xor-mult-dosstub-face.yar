rule TTP_XOR_MULT_DOSStub_face {
  strings:
    $key_face = { ae a6 [2] da be [2] 9d bc [2] da ad [2] 94 a1 [2] 98 ab [2] 8f a0 [2] 94 ee [2] a9 }

  condition:
    any of them
}