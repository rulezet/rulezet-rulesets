rule TTP_XOR_MULT_DOSStub_24ce {
  strings:
    $key_24ce = { 70 a6 [2] 04 be [2] 43 bc [2] 04 ad [2] 4a a1 [2] 46 ab [2] 51 a0 [2] 4a ee [2] 77 }

  condition:
    any of them
}