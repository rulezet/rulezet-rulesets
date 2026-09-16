rule TTP_XOR_MULT_DOSStub_199e {
  strings:
    $key_199e = { 4d f6 [2] 39 ee [2] 7e ec [2] 39 fd [2] 77 f1 [2] 7b fb [2] 6c f0 [2] 77 be [2] 4a }

  condition:
    any of them
}