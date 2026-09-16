rule TTP_XOR_MULT_DOSStub_18ce {
  strings:
    $key_18ce = { 4c a6 [2] 38 be [2] 7f bc [2] 38 ad [2] 76 a1 [2] 7a ab [2] 6d a0 [2] 76 ee [2] 4b }

  condition:
    any of them
}