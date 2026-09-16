rule TTP_XOR_MULT_DOSStub_d08d {
  strings:
    $key_d08d = { 84 e5 [2] f0 fd [2] b7 ff [2] f0 ee [2] be e2 [2] b2 e8 [2] a5 e3 [2] be ad [2] 83 }

  condition:
    any of them
}