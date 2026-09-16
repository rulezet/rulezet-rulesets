rule TTP_XOR_MULT_DOSStub_2bc6 {
  strings:
    $key_2bc6 = { 7f ae [2] 0b b6 [2] 4c b4 [2] 0b a5 [2] 45 a9 [2] 49 a3 [2] 5e a8 [2] 45 e6 [2] 78 }

  condition:
    any of them
}