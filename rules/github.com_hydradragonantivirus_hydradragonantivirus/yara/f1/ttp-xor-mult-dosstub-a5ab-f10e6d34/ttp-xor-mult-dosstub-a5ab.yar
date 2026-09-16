rule TTP_XOR_MULT_DOSStub_a5ab {
  strings:
    $key_a5ab = { f1 c3 [2] 85 db [2] c2 d9 [2] 85 c8 [2] cb c4 [2] c7 ce [2] d0 c5 [2] cb 8b [2] f6 }

  condition:
    any of them
}