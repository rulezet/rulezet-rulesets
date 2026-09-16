rule TTP_XOR_MULT_DOSStub_81df {
  strings:
    $key_81df = { d5 b7 [2] a1 af [2] e6 ad [2] a1 bc [2] ef b0 [2] e3 ba [2] f4 b1 [2] ef ff [2] d2 }

  condition:
    any of them
}