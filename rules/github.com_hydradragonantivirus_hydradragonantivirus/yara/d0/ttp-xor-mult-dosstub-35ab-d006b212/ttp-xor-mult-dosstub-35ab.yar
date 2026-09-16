rule TTP_XOR_MULT_DOSStub_35ab {
  strings:
    $key_35ab = { 61 c3 [2] 15 db [2] 52 d9 [2] 15 c8 [2] 5b c4 [2] 57 ce [2] 40 c5 [2] 5b 8b [2] 66 }

  condition:
    any of them
}