rule TTP_XOR_MULT_DOSStub_73ce {
  strings:
    $key_73ce = { 27 a6 [2] 53 be [2] 14 bc [2] 53 ad [2] 1d a1 [2] 11 ab [2] 06 a0 [2] 1d ee [2] 20 }

  condition:
    any of them
}