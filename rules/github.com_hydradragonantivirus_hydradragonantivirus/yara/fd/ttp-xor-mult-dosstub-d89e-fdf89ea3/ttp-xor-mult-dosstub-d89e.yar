rule TTP_XOR_MULT_DOSStub_d89e {
  strings:
    $key_d89e = { 8c f6 [2] f8 ee [2] bf ec [2] f8 fd [2] b6 f1 [2] ba fb [2] ad f0 [2] b6 be [2] 8b }

  condition:
    any of them
}