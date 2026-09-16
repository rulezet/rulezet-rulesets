rule TTP_XOR_MULT_DOSStub_6bc6 {
  strings:
    $key_6bc6 = { 3f ae [2] 4b b6 [2] 0c b4 [2] 4b a5 [2] 05 a9 [2] 09 a3 [2] 1e a8 [2] 05 e6 [2] 38 }

  condition:
    any of them
}