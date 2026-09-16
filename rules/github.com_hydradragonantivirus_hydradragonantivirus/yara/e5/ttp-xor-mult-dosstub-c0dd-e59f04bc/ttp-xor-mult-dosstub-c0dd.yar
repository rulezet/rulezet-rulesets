rule TTP_XOR_MULT_DOSStub_c0dd {
  strings:
    $key_c0dd = { 94 b5 [2] e0 ad [2] a7 af [2] e0 be [2] ae b2 [2] a2 b8 [2] b5 b3 [2] ae fd [2] 93 }

  condition:
    any of them
}