rule TTP_XOR_MULT_DOSStub_00ab {
  strings:
    $key_00ab = { 54 c3 [2] 20 db [2] 67 d9 [2] 20 c8 [2] 6e c4 [2] 62 ce [2] 75 c5 [2] 6e 8b [2] 53 }

  condition:
    any of them
}