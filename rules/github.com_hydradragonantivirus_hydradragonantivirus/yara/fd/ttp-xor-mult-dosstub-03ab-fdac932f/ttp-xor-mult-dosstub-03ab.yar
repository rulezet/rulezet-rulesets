rule TTP_XOR_MULT_DOSStub_03ab {
  strings:
    $key_03ab = { 57 c3 [2] 23 db [2] 64 d9 [2] 23 c8 [2] 6d c4 [2] 61 ce [2] 76 c5 [2] 6d 8b [2] 50 }

  condition:
    any of them
}