rule TTP_XOR_MULT_DOSStub_4c93 {
  strings:
    $key_4c93 = { 18 fb [2] 6c e3 [2] 2b e1 [2] 6c f0 [2] 22 fc [2] 2e f6 [2] 39 fd [2] 22 b3 [2] 1f }

  condition:
    any of them
}