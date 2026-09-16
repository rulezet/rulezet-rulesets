rule TTP_XOR_MULT_DOSStub_78ab {
  strings:
    $key_78ab = { 2c c3 [2] 58 db [2] 1f d9 [2] 58 c8 [2] 16 c4 [2] 1a ce [2] 0d c5 [2] 16 8b [2] 2b }

  condition:
    any of them
}