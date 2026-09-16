rule TTP_XOR_MULT_DOSStub_22dd {
  strings:
    $key_22dd = { 76 b5 [2] 02 ad [2] 45 af [2] 02 be [2] 4c b2 [2] 40 b8 [2] 57 b3 [2] 4c fd [2] 71 }

  condition:
    any of them
}