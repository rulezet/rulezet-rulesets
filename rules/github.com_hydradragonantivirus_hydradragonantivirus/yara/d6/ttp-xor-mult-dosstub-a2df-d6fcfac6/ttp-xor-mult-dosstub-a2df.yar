rule TTP_XOR_MULT_DOSStub_a2df {
  strings:
    $key_a2df = { f6 b7 [2] 82 af [2] c5 ad [2] 82 bc [2] cc b0 [2] c0 ba [2] d7 b1 [2] cc ff [2] f1 }

  condition:
    any of them
}