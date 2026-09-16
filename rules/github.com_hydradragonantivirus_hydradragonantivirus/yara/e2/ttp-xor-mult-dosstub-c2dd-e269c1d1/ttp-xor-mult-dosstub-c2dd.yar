rule TTP_XOR_MULT_DOSStub_c2dd {
  strings:
    $key_c2dd = { 96 b5 [2] e2 ad [2] a5 af [2] e2 be [2] ac b2 [2] a0 b8 [2] b7 b3 [2] ac fd [2] 91 }

  condition:
    any of them
}