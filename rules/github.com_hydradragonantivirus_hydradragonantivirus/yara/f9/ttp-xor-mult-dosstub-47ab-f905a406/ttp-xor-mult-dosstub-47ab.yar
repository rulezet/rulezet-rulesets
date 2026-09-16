rule TTP_XOR_MULT_DOSStub_47ab {
  strings:
    $key_47ab = { 13 c3 [2] 67 db [2] 20 d9 [2] 67 c8 [2] 29 c4 [2] 25 ce [2] 32 c5 [2] 29 8b [2] 14 }

  condition:
    any of them
}