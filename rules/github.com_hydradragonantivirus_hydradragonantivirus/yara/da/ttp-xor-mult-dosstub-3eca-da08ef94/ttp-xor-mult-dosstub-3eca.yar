rule TTP_XOR_MULT_DOSStub_3eca {
  strings:
    $key_3eca = { 6a a2 [2] 1e ba [2] 59 b8 [2] 1e a9 [2] 50 a5 [2] 5c af [2] 4b a4 [2] 50 ea [2] 6d }

  condition:
    any of them
}