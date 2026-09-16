rule TTP_XOR_MULT_DOSStub_d49e {
  strings:
    $key_d49e = { 80 f6 [2] f4 ee [2] b3 ec [2] f4 fd [2] ba f1 [2] b6 fb [2] a1 f0 [2] ba be [2] 87 }

  condition:
    any of them
}