rule TTP_XOR_MULT_DOSStub_56a6 {
  strings:
    $key_56a6 = { 02 ce [2] 76 d6 [2] 31 d4 [2] 76 c5 [2] 38 c9 [2] 34 c3 [2] 23 c8 [2] 38 86 [2] 05 }

  condition:
    any of them
}