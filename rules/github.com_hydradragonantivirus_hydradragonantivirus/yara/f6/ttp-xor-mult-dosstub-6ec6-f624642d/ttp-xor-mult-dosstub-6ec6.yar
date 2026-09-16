rule TTP_XOR_MULT_DOSStub_6ec6 {
  strings:
    $key_6ec6 = { 3a ae [2] 4e b6 [2] 09 b4 [2] 4e a5 [2] 00 a9 [2] 0c a3 [2] 1b a8 [2] 00 e6 [2] 3d }

  condition:
    any of them
}