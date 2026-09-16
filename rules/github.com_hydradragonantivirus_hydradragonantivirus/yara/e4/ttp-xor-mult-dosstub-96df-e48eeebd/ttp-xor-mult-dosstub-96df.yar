rule TTP_XOR_MULT_DOSStub_96df {
  strings:
    $key_96df = { c2 b7 [2] b6 af [2] f1 ad [2] b6 bc [2] f8 b0 [2] f4 ba [2] e3 b1 [2] f8 ff [2] c5 }

  condition:
    any of them
}