rule TTP_XOR_MULT_DOSStub_04dd {
  strings:
    $key_04dd = { 50 b5 [2] 24 ad [2] 63 af [2] 24 be [2] 6a b2 [2] 66 b8 [2] 71 b3 [2] 6a fd [2] 57 }

  condition:
    any of them
}