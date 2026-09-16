rule TTP_XOR_MULT_DOSStub_5b8d {
  strings:
    $key_5b8d = { 0f e5 [2] 7b fd [2] 3c ff [2] 7b ee [2] 35 e2 [2] 39 e8 [2] 2e e3 [2] 35 ad [2] 08 }

  condition:
    any of them
}