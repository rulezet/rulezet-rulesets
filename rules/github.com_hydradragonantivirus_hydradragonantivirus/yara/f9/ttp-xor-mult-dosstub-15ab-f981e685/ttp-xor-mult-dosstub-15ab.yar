rule TTP_XOR_MULT_DOSStub_15ab {
  strings:
    $key_15ab = { 41 c3 [2] 35 db [2] 72 d9 [2] 35 c8 [2] 7b c4 [2] 77 ce [2] 60 c5 [2] 7b 8b [2] 46 }

  condition:
    any of them
}