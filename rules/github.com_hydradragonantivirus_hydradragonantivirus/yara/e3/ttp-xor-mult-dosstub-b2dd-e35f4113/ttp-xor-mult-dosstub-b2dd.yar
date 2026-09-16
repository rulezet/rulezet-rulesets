rule TTP_XOR_MULT_DOSStub_b2dd {
  strings:
    $key_b2dd = { e6 b5 [2] 92 ad [2] d5 af [2] 92 be [2] dc b2 [2] d0 b8 [2] c7 b3 [2] dc fd [2] e1 }

  condition:
    any of them
}