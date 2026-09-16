rule TTP_XOR_MULT_DOSStub_189e {
  strings:
    $key_189e = { 4c f6 [2] 38 ee [2] 7f ec [2] 38 fd [2] 76 f1 [2] 7a fb [2] 6d f0 [2] 76 be [2] 4b }

  condition:
    any of them
}