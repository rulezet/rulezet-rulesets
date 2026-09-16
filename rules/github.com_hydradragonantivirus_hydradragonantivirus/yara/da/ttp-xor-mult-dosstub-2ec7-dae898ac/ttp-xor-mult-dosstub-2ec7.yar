rule TTP_XOR_MULT_DOSStub_2ec7 {
  strings:
    $key_2ec7 = { 7a af [2] 0e b7 [2] 49 b5 [2] 0e a4 [2] 40 a8 [2] 4c a2 [2] 5b a9 [2] 40 e7 [2] 7d }

  condition:
    any of them
}