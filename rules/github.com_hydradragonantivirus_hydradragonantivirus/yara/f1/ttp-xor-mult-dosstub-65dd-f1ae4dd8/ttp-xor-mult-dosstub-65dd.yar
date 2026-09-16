rule TTP_XOR_MULT_DOSStub_65dd {
  strings:
    $key_65dd = { 31 b5 [2] 45 ad [2] 02 af [2] 45 be [2] 0b b2 [2] 07 b8 [2] 10 b3 [2] 0b fd [2] 36 }

  condition:
    any of them
}