rule TTP_XOR_MULT_DOSStub_3a8d {
  strings:
    $key_3a8d = { 6e e5 [2] 1a fd [2] 5d ff [2] 1a ee [2] 54 e2 [2] 58 e8 [2] 4f e3 [2] 54 ad [2] 69 }

  condition:
    any of them
}