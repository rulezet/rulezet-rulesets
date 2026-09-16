rule TTP_XOR_MULT_DOSStub_c6df {
  strings:
    $key_c6df = { 92 b7 [2] e6 af [2] a1 ad [2] e6 bc [2] a8 b0 [2] a4 ba [2] b3 b1 [2] a8 ff [2] 95 }

  condition:
    any of them
}