rule TTP_XOR_MULT_DOSStub_1c93 {
  strings:
    $key_1c93 = { 48 fb [2] 3c e3 [2] 7b e1 [2] 3c f0 [2] 72 fc [2] 7e f6 [2] 69 fd [2] 72 b3 [2] 4f }

  condition:
    any of them
}