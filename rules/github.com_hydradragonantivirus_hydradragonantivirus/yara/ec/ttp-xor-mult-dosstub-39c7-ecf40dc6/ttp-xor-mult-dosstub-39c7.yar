rule TTP_XOR_MULT_DOSStub_39c7 {
  strings:
    $key_39c7 = { 6d af [2] 19 b7 [2] 5e b5 [2] 19 a4 [2] 57 a8 [2] 5b a2 [2] 4c a9 [2] 57 e7 [2] 6a }

  condition:
    any of them
}