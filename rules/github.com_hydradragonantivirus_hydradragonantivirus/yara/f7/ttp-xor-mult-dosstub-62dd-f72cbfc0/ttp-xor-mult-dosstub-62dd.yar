rule TTP_XOR_MULT_DOSStub_62dd {
  strings:
    $key_62dd = { 36 b5 [2] 42 ad [2] 05 af [2] 42 be [2] 0c b2 [2] 00 b8 [2] 17 b3 [2] 0c fd [2] 31 }

  condition:
    any of them
}