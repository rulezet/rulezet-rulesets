rule TTP_XOR_MULT_DOSStub_7eca {
  strings:
    $key_7eca = { 2a a2 [2] 5e ba [2] 19 b8 [2] 5e a9 [2] 10 a5 [2] 1c af [2] 0b a4 [2] 10 ea [2] 2d }

  condition:
    any of them
}