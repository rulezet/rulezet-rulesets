rule TTP_XOR_MULT_DOSStub_48ce {
  strings:
    $key_48ce = { 1c a6 [2] 68 be [2] 2f bc [2] 68 ad [2] 26 a1 [2] 2a ab [2] 3d a0 [2] 26 ee [2] 1b }

  condition:
    any of them
}