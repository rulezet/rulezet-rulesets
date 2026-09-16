rule TTP_XOR_MULT_DOSStub_14a6 {
  strings:
    $key_14a6 = { 40 ce [2] 34 d6 [2] 73 d4 [2] 34 c5 [2] 7a c9 [2] 76 c3 [2] 61 c8 [2] 7a 86 [2] 47 }

  condition:
    any of them
}