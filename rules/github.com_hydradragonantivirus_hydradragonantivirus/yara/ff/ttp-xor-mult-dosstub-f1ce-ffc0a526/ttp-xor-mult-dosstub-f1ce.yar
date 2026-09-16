rule TTP_XOR_MULT_DOSStub_f1ce {
  strings:
    $key_f1ce = { a5 a6 [2] d1 be [2] 96 bc [2] d1 ad [2] 9f a1 [2] 93 ab [2] 84 a0 [2] 9f ee [2] a2 }

  condition:
    any of them
}