rule TTP_XOR_MULT_DOSStub_6ec7 {
  strings:
    $key_6ec7 = { 3a af [2] 4e b7 [2] 09 b5 [2] 4e a4 [2] 00 a8 [2] 0c a2 [2] 1b a9 [2] 00 e7 [2] 3d }

  condition:
    any of them
}