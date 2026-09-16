rule TTP_XOR_MULT_DOSStub_908b {
  strings:
    $key_908b = { c4 e3 [2] b0 fb [2] f7 f9 [2] b0 e8 [2] fe e4 [2] f2 ee [2] e5 e5 [2] fe ab [2] c3 }

  condition:
    any of them
}