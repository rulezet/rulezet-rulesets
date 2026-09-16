rule TTP_XOR_MULT_DOSStub_38dd {
  strings:
    $key_38dd = { 6c b5 [2] 18 ad [2] 5f af [2] 18 be [2] 56 b2 [2] 5a b8 [2] 4d b3 [2] 56 fd [2] 6b }

  condition:
    any of them
}