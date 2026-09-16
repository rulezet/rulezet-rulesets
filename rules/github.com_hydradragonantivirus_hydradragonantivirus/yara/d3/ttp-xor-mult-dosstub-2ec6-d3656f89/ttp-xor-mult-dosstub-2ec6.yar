rule TTP_XOR_MULT_DOSStub_2ec6 {
  strings:
    $key_2ec6 = { 7a ae [2] 0e b6 [2] 49 b4 [2] 0e a5 [2] 40 a9 [2] 4c a3 [2] 5b a8 [2] 40 e6 [2] 7d }

  condition:
    any of them
}