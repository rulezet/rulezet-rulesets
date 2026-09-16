rule TTP_XOR_MULT_DOSStub_49c7 {
  strings:
    $key_49c7 = { 1d af [2] 69 b7 [2] 2e b5 [2] 69 a4 [2] 27 a8 [2] 2b a2 [2] 3c a9 [2] 27 e7 [2] 1a }

  condition:
    any of them
}