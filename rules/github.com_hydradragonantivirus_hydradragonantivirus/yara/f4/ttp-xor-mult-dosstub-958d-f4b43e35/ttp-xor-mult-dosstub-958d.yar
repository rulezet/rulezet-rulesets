rule TTP_XOR_MULT_DOSStub_958d {
  strings:
    $key_958d = { c1 e5 [2] b5 fd [2] f2 ff [2] b5 ee [2] fb e2 [2] f7 e8 [2] e0 e3 [2] fb ad [2] c6 }

  condition:
    any of them
}