rule TTP_XOR_MULT_DOSStub_65a6 {
  strings:
    $key_65a6 = { 31 ce [2] 45 d6 [2] 02 d4 [2] 45 c5 [2] 0b c9 [2] 07 c3 [2] 10 c8 [2] 0b 86 [2] 36 }

  condition:
    any of them
}