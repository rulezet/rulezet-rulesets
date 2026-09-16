rule TTP_XOR_MULT_DOSStub_39dd {
  strings:
    $key_39dd = { 6d b5 [2] 19 ad [2] 5e af [2] 19 be [2] 57 b2 [2] 5b b8 [2] 4c b3 [2] 57 fd [2] 6a }

  condition:
    any of them
}