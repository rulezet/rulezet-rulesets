rule TTP_XOR_MULT_DOSStub_c0df {
  strings:
    $key_c0df = { 94 b7 [2] e0 af [2] a7 ad [2] e0 bc [2] ae b0 [2] a2 ba [2] b5 b1 [2] ae ff [2] 93 }

  condition:
    any of them
}