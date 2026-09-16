rule TTP_XOR_MULT_DOSStub_37ab {
  strings:
    $key_37ab = { 63 c3 [2] 17 db [2] 50 d9 [2] 17 c8 [2] 59 c4 [2] 55 ce [2] 42 c5 [2] 59 8b [2] 64 }

  condition:
    any of them
}