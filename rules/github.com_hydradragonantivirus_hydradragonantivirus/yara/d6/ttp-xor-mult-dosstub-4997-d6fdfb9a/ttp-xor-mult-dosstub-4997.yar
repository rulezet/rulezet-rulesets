rule TTP_XOR_MULT_DOSStub_4997 {
  strings:
    $key_4997 = { 1d ff [2] 69 e7 [2] 2e e5 [2] 69 f4 [2] 27 f8 [2] 2b f2 [2] 3c f9 [2] 27 b7 [2] 1a }

  condition:
    any of them
}