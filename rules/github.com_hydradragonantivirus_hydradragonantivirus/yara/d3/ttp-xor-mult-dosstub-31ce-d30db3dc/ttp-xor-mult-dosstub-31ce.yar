rule TTP_XOR_MULT_DOSStub_31ce {
  strings:
    $key_31ce = { 65 a6 [2] 11 be [2] 56 bc [2] 11 ad [2] 5f a1 [2] 53 ab [2] 44 a0 [2] 5f ee [2] 62 }

  condition:
    any of them
}