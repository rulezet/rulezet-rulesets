rule TTP_XOR_MULT_DOSStub_f2dd {
  strings:
    $key_f2dd = { a6 b5 [2] d2 ad [2] 95 af [2] d2 be [2] 9c b2 [2] 90 b8 [2] 87 b3 [2] 9c fd [2] a1 }

  condition:
    any of them
}