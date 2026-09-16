rule TTP_XOR_MULT_DOSStub_70ab {
  strings:
    $key_70ab = { 24 c3 [2] 50 db [2] 17 d9 [2] 50 c8 [2] 1e c4 [2] 12 ce [2] 05 c5 [2] 1e 8b [2] 23 }

  condition:
    any of them
}