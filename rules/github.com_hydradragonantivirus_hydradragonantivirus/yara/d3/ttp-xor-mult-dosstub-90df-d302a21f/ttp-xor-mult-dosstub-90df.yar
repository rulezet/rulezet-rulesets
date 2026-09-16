rule TTP_XOR_MULT_DOSStub_90df {
  strings:
    $key_90df = { c4 b7 [2] b0 af [2] f7 ad [2] b0 bc [2] fe b0 [2] f2 ba [2] e5 b1 [2] fe ff [2] c3 }

  condition:
    any of them
}