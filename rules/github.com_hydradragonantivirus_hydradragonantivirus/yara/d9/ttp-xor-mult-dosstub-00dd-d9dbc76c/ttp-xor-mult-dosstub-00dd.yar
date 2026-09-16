rule TTP_XOR_MULT_DOSStub_00dd {
  strings:
    $key_00dd = { 54 b5 [2] 20 ad [2] 67 af [2] 20 be [2] 6e b2 [2] 62 b8 [2] 75 b3 [2] 6e fd [2] 53 }

  condition:
    any of them
}