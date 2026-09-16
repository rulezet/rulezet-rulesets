rule TTP_XOR_MULT_DOSStub_58ce {
  strings:
    $key_58ce = { 0c a6 [2] 78 be [2] 3f bc [2] 78 ad [2] 36 a1 [2] 3a ab [2] 2d a0 [2] 36 ee [2] 0b }

  condition:
    any of them
}