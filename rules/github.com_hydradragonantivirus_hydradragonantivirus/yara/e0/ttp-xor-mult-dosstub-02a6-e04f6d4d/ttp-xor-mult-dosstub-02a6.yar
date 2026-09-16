rule TTP_XOR_MULT_DOSStub_02a6 {
  strings:
    $key_02a6 = { 56 ce [2] 22 d6 [2] 65 d4 [2] 22 c5 [2] 6c c9 [2] 60 c3 [2] 77 c8 [2] 6c 86 [2] 51 }

  condition:
    any of them
}