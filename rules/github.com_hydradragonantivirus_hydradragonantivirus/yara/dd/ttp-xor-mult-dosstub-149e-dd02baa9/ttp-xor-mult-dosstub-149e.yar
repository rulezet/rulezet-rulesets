rule TTP_XOR_MULT_DOSStub_149e {
  strings:
    $key_149e = { 40 f6 [2] 34 ee [2] 73 ec [2] 34 fd [2] 7a f1 [2] 76 fb [2] 61 f0 [2] 7a be [2] 47 }

  condition:
    any of them
}