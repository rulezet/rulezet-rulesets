rule TTP_XOR_MULT_DOSStub_2eca {
  strings:
    $key_2eca = { 7a a2 [2] 0e ba [2] 49 b8 [2] 0e a9 [2] 40 a5 [2] 4c af [2] 5b a4 [2] 40 ea [2] 7d }

  condition:
    any of them
}