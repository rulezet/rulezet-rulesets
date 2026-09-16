rule TTP_XOR_MULT_DOSStub_399e {
  strings:
    $key_399e = { 6d f6 [2] 19 ee [2] 5e ec [2] 19 fd [2] 57 f1 [2] 5b fb [2] 4c f0 [2] 57 be [2] 6a }

  condition:
    any of them
}