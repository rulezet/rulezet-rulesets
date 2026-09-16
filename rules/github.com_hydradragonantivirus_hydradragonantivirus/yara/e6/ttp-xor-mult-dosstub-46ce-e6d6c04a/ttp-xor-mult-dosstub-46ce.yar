rule TTP_XOR_MULT_DOSStub_46ce {
  strings:
    $key_46ce = { 12 a6 [2] 66 be [2] 21 bc [2] 66 ad [2] 28 a1 [2] 24 ab [2] 33 a0 [2] 28 ee [2] 15 }

  condition:
    any of them
}