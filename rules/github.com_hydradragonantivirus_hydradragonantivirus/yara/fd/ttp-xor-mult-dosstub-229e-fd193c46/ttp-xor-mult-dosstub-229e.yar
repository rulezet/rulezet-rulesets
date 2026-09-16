rule TTP_XOR_MULT_DOSStub_229e {
  strings:
    $key_229e = { 76 f6 [2] 02 ee [2] 45 ec [2] 02 fd [2] 4c f1 [2] 40 fb [2] 57 f0 [2] 4c be [2] 71 }

  condition:
    any of them
}