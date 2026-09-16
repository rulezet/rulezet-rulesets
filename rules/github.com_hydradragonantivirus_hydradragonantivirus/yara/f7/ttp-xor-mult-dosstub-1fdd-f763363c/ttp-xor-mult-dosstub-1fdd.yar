rule TTP_XOR_MULT_DOSStub_1fdd {
  strings:
    $key_1fdd = { 4b b5 [2] 3f ad [2] 78 af [2] 3f be [2] 71 b2 [2] 7d b8 [2] 6a b3 [2] 71 fd [2] 4c }

  condition:
    any of them
}