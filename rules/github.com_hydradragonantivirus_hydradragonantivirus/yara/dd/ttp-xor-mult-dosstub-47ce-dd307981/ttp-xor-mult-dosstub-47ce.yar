rule TTP_XOR_MULT_DOSStub_47ce {
  strings:
    $key_47ce = { 13 a6 [2] 67 be [2] 20 bc [2] 67 ad [2] 29 a1 [2] 25 ab [2] 32 a0 [2] 29 ee [2] 14 }

  condition:
    any of them
}