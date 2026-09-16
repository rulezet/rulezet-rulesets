rule TTP_XOR_MULT_DOSStub_36ab {
  strings:
    $key_36ab = { 62 c3 [2] 16 db [2] 51 d9 [2] 16 c8 [2] 58 c4 [2] 54 ce [2] 43 c5 [2] 58 8b [2] 65 }

  condition:
    any of them
}