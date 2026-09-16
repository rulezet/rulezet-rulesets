rule TTP_XOR_MULT_DOSStub_81dd {
  strings:
    $key_81dd = { d5 b5 [2] a1 ad [2] e6 af [2] a1 be [2] ef b2 [2] e3 b8 [2] f4 b3 [2] ef fd [2] d2 }

  condition:
    any of them
}