rule TTP_XOR_MULT_DOSStub_66ab {
  strings:
    $key_66ab = { 32 c3 [2] 46 db [2] 01 d9 [2] 46 c8 [2] 08 c4 [2] 04 ce [2] 13 c5 [2] 08 8b [2] 35 }

  condition:
    any of them
}