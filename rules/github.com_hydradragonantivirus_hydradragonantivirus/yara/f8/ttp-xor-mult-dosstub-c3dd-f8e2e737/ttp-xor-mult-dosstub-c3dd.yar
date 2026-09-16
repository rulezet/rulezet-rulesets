rule TTP_XOR_MULT_DOSStub_c3dd {
  strings:
    $key_c3dd = { 97 b5 [2] e3 ad [2] a4 af [2] e3 be [2] ad b2 [2] a1 b8 [2] b6 b3 [2] ad fd [2] 90 }

  condition:
    any of them
}