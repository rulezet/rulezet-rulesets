rule TTP_XOR_MULT_DOSStub_c7dd {
  strings:
    $key_c7dd = { 93 b5 [2] e7 ad [2] a0 af [2] e7 be [2] a9 b2 [2] a5 b8 [2] b2 b3 [2] a9 fd [2] 94 }

  condition:
    any of them
}