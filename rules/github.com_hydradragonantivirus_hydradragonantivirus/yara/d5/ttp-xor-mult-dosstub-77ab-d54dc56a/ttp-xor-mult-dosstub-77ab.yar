rule TTP_XOR_MULT_DOSStub_77ab {
  strings:
    $key_77ab = { 23 c3 [2] 57 db [2] 10 d9 [2] 57 c8 [2] 19 c4 [2] 15 ce [2] 02 c5 [2] 19 8b [2] 24 }

  condition:
    any of them
}