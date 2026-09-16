rule TTP_XOR_MULT_DOSStub_e6df {
  strings:
    $key_e6df = { b2 b7 [2] c6 af [2] 81 ad [2] c6 bc [2] 88 b0 [2] 84 ba [2] 93 b1 [2] 88 ff [2] b5 }

  condition:
    any of them
}