rule TTP_XOR_MULT_DOSStub_329e {
  strings:
    $key_329e = { 66 f6 [2] 12 ee [2] 55 ec [2] 12 fd [2] 5c f1 [2] 50 fb [2] 47 f0 [2] 5c be [2] 61 }

  condition:
    any of them
}