rule TTP_XOR_MULT_DOSStub_32a6 {
  strings:
    $key_32a6 = { 66 ce [2] 12 d6 [2] 55 d4 [2] 12 c5 [2] 5c c9 [2] 50 c3 [2] 47 c8 [2] 5c 86 [2] 61 }

  condition:
    any of them
}