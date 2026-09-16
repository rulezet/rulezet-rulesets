rule TTP_XOR_MULT_DOSStub_bbb9 {
  strings:
    $key_bbb9 = { ef d1 [2] 9b c9 [2] dc cb [2] 9b da [2] d5 d6 [2] d9 dc [2] ce d7 [2] d5 99 [2] e8 }

  condition:
    any of them
}