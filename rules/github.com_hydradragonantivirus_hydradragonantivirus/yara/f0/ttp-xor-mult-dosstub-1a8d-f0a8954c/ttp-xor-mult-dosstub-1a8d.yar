rule TTP_XOR_MULT_DOSStub_1a8d {
  strings:
    $key_1a8d = { 4e e5 [2] 3a fd [2] 7d ff [2] 3a ee [2] 74 e2 [2] 78 e8 [2] 6f e3 [2] 74 ad [2] 49 }

  condition:
    any of them
}