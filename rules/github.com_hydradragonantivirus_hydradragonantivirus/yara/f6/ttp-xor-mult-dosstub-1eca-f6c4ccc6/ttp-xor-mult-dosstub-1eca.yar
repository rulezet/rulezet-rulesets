rule TTP_XOR_MULT_DOSStub_1eca {
  strings:
    $key_1eca = { 4a a2 [2] 3e ba [2] 79 b8 [2] 3e a9 [2] 70 a5 [2] 7c af [2] 6b a4 [2] 70 ea [2] 4d }

  condition:
    any of them
}