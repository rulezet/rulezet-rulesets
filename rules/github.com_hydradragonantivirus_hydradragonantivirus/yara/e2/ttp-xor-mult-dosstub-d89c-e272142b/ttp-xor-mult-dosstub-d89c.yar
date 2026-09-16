rule TTP_XOR_MULT_DOSStub_d89c {
  strings:
    $key_d89c = { 8c f4 [2] f8 ec [2] bf ee [2] f8 ff [2] b6 f3 [2] ba f9 [2] ad f2 [2] b6 bc [2] 8b }

  condition:
    any of them
}