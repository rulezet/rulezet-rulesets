rule TTP_XOR_MULT_DOSStub_7ec6 {
  strings:
    $key_7ec6 = { 2a ae [2] 5e b6 [2] 19 b4 [2] 5e a5 [2] 10 a9 [2] 1c a3 [2] 0b a8 [2] 10 e6 [2] 2d }

  condition:
    any of them
}