rule TTP_XOR_MULT_DOSStub_7c93 {
  strings:
    $key_7c93 = { 28 fb [2] 5c e3 [2] 1b e1 [2] 5c f0 [2] 12 fc [2] 1e f6 [2] 09 fd [2] 12 b3 [2] 2f }

  condition:
    any of them
}