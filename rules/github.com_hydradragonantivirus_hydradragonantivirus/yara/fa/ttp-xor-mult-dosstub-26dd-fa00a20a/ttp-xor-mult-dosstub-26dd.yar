rule TTP_XOR_MULT_DOSStub_26dd {
  strings:
    $key_26dd = { 72 b5 [2] 06 ad [2] 41 af [2] 06 be [2] 48 b2 [2] 44 b8 [2] 53 b3 [2] 48 fd [2] 75 }

  condition:
    any of them
}