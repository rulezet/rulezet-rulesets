rule TTP_XOR_MULT_DOSStub_868d {
  strings:
    $key_868d = { d2 e5 [2] a6 fd [2] e1 ff [2] a6 ee [2] e8 e2 [2] e4 e8 [2] f3 e3 [2] e8 ad [2] d5 }

  condition:
    any of them
}