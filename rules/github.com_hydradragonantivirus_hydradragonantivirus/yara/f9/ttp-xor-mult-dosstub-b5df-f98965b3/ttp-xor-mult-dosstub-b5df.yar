rule TTP_XOR_MULT_DOSStub_b5df {
  strings:
    $key_b5df = { e1 b7 [2] 95 af [2] d2 ad [2] 95 bc [2] db b0 [2] d7 ba [2] c0 b1 [2] db ff [2] e6 }

  condition:
    any of them
}