rule TTP_XOR_MULT_DOSStub_63ab {
  strings:
    $key_63ab = { 37 c3 [2] 43 db [2] 04 d9 [2] 43 c8 [2] 0d c4 [2] 01 ce [2] 16 c5 [2] 0d 8b [2] 30 }

  condition:
    any of them
}