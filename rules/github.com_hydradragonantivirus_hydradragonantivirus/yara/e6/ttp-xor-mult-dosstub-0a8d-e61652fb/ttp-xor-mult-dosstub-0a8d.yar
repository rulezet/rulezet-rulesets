rule TTP_XOR_MULT_DOSStub_0a8d {
  strings:
    $key_0a8d = { 5e e5 [2] 2a fd [2] 6d ff [2] 2a ee [2] 64 e2 [2] 68 e8 [2] 7f e3 [2] 64 ad [2] 59 }

  condition:
    any of them
}