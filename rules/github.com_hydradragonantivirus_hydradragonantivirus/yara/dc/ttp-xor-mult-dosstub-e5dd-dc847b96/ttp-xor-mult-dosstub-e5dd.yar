rule TTP_XOR_MULT_DOSStub_e5dd {
  strings:
    $key_e5dd = { b1 b5 [2] c5 ad [2] 82 af [2] c5 be [2] 8b b2 [2] 87 b8 [2] 90 b3 [2] 8b fd [2] b6 }

  condition:
    any of them
}