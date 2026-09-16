rule TTP_XOR_MULT_DOSStub_54dd {
  strings:
    $key_54dd = { 00 b5 [2] 74 ad [2] 33 af [2] 74 be [2] 3a b2 [2] 36 b8 [2] 21 b3 [2] 3a fd [2] 07 }

  condition:
    any of them
}