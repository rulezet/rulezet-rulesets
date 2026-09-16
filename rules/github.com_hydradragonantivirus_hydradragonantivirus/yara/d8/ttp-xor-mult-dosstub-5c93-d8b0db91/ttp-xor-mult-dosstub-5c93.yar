rule TTP_XOR_MULT_DOSStub_5c93 {
  strings:
    $key_5c93 = { 08 fb [2] 7c e3 [2] 3b e1 [2] 7c f0 [2] 32 fc [2] 3e f6 [2] 29 fd [2] 32 b3 [2] 0f }

  condition:
    any of them
}