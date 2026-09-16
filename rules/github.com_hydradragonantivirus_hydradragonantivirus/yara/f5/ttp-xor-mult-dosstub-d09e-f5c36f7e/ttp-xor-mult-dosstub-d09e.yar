rule TTP_XOR_MULT_DOSStub_d09e {
  strings:
    $key_d09e = { 84 f6 [2] f0 ee [2] b7 ec [2] f0 fd [2] be f1 [2] b2 fb [2] a5 f0 [2] be be [2] 83 }

  condition:
    any of them
}