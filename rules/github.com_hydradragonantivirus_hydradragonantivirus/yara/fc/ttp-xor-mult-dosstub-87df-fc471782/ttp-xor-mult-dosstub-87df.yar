rule TTP_XOR_MULT_DOSStub_87df {
  strings:
    $key_87df = { d3 b7 [2] a7 af [2] e0 ad [2] a7 bc [2] e9 b0 [2] e5 ba [2] f2 b1 [2] e9 ff [2] d4 }

  condition:
    any of them
}