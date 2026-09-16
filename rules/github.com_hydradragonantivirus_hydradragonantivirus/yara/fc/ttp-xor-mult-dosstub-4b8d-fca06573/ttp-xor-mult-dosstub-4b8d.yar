rule TTP_XOR_MULT_DOSStub_4b8d {
  strings:
    $key_4b8d = { 1f e5 [2] 6b fd [2] 2c ff [2] 6b ee [2] 25 e2 [2] 29 e8 [2] 3e e3 [2] 25 ad [2] 18 }

  condition:
    any of them
}