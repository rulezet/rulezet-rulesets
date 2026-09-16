rule TTP_XOR_MULT_DOSStub_4037 {
  strings:
    $key_4037 = { 14 5f [2] 60 47 [2] 27 45 [2] 60 54 [2] 2e 58 [2] 22 52 [2] 35 59 [2] 2e 17 [2] 13 }

  condition:
    any of them
}