rule TTP_XOR_MULT_DOSStub_29dd {
  strings:
    $key_29dd = { 7d b5 [2] 09 ad [2] 4e af [2] 09 be [2] 47 b2 [2] 4b b8 [2] 5c b3 [2] 47 fd [2] 7a }

  condition:
    any of them
}