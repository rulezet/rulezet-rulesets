rule TTP_XOR_MULT_DOSStub_5cc6 {
  strings:
    $key_5cc6 = { 08 ae [2] 7c b6 [2] 3b b4 [2] 7c a5 [2] 32 a9 [2] 3e a3 [2] 29 a8 [2] 32 e6 [2] 0f }

  condition:
    any of them
}