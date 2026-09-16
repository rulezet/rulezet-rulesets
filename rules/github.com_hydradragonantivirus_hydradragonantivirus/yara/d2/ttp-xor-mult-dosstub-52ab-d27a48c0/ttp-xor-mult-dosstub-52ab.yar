rule TTP_XOR_MULT_DOSStub_52ab {
  strings:
    $key_52ab = { 06 c3 [2] 72 db [2] 35 d9 [2] 72 c8 [2] 3c c4 [2] 30 ce [2] 27 c5 [2] 3c 8b [2] 01 }

  condition:
    any of them
}