rule TTP_XOR_MULT_DOSStub_50ab {
  strings:
    $key_50ab = { 04 c3 [2] 70 db [2] 37 d9 [2] 70 c8 [2] 3e c4 [2] 32 ce [2] 25 c5 [2] 3e 8b [2] 03 }

  condition:
    any of them
}