rule TTP_XOR_MULT_DOSStub_1240 {
  strings:
    $key_1240 = { 46 28 [2] 32 30 [2] 75 32 [2] 32 23 [2] 7c 2f [2] 70 25 [2] 67 2e [2] 7c 60 [2] 41 }

  condition:
    any of them
}