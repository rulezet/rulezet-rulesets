rule TTP_XOR_MULT_DOSStub_b19e {
  strings:
    $key_b19e = { e5 f6 [2] 91 ee [2] d6 ec [2] 91 fd [2] df f1 [2] d3 fb [2] c4 f0 [2] df be [2] e2 }

  condition:
    any of them
}