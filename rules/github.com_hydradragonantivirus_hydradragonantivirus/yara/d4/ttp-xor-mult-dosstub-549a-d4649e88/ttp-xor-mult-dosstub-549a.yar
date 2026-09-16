rule TTP_XOR_MULT_DOSStub_549a {
  strings:
    $key_549a = { 00 f2 [2] 74 ea [2] 33 e8 [2] 74 f9 [2] 3a f5 [2] 36 ff [2] 21 f4 [2] 3a ba [2] 07 }

  condition:
    any of them
}