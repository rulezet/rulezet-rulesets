rule TTP_XOR_MULT_DOSStub_2a8d {
  strings:
    $key_2a8d = { 7e e5 [2] 0a fd [2] 4d ff [2] 0a ee [2] 44 e2 [2] 48 e8 [2] 5f e3 [2] 44 ad [2] 79 }

  condition:
    any of them
}