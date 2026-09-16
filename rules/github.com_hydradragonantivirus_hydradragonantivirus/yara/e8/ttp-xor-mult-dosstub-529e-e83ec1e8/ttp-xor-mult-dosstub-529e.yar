rule TTP_XOR_MULT_DOSStub_529e {
  strings:
    $key_529e = { 06 f6 [2] 72 ee [2] 35 ec [2] 72 fd [2] 3c f1 [2] 30 fb [2] 27 f0 [2] 3c be [2] 01 }

  condition:
    any of them
}