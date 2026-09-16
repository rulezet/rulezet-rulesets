rule TTP_XOR_MULT_DOSStub_25dd {
  strings:
    $key_25dd = { 71 b5 [2] 05 ad [2] 42 af [2] 05 be [2] 4b b2 [2] 47 b8 [2] 50 b3 [2] 4b fd [2] 76 }

  condition:
    any of them
}