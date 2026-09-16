rule TTP_XOR_MULT_DOSStub_12dd {
  strings:
    $key_12dd = { 46 b5 [2] 32 ad [2] 75 af [2] 32 be [2] 7c b2 [2] 70 b8 [2] 67 b3 [2] 7c fd [2] 41 }

  condition:
    any of them
}