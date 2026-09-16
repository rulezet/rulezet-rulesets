rule TTP_XOR_MULT_DOSStub_5ec7 {
  strings:
    $key_5ec7 = { 0a af [2] 7e b7 [2] 39 b5 [2] 7e a4 [2] 30 a8 [2] 3c a2 [2] 2b a9 [2] 30 e7 [2] 0d }

  condition:
    any of them
}