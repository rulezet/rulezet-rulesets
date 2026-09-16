rule TTP_XOR_MULT_DOSStub_7fdd {
  strings:
    $key_7fdd = { 2b b5 [2] 5f ad [2] 18 af [2] 5f be [2] 11 b2 [2] 1d b8 [2] 0a b3 [2] 11 fd [2] 2c }

  condition:
    any of them
}