rule TTP_XOR_MULT_DOSStub_78ce {
  strings:
    $key_78ce = { 2c a6 [2] 58 be [2] 1f bc [2] 58 ad [2] 16 a1 [2] 1a ab [2] 0d a0 [2] 16 ee [2] 2b }

  condition:
    any of them
}