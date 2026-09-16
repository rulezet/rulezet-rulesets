rule TTP_XOR_MULT_DOSStub_75ce {
  strings:
    $key_75ce = { 21 a6 [2] 55 be [2] 12 bc [2] 55 ad [2] 1b a1 [2] 17 ab [2] 00 a0 [2] 1b ee [2] 26 }

  condition:
    any of them
}