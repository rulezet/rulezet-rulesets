rule TTP_XOR_MULT_DOSStub_1ec7 {
  strings:
    $key_1ec7 = { 4a af [2] 3e b7 [2] 79 b5 [2] 3e a4 [2] 70 a8 [2] 7c a2 [2] 6b a9 [2] 70 e7 [2] 4d }

  condition:
    any of them
}