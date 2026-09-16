rule TTP_XOR_MULT_DOSStub_06ab {
  strings:
    $key_06ab = { 52 c3 [2] 26 db [2] 61 d9 [2] 26 c8 [2] 68 c4 [2] 64 ce [2] 73 c5 [2] 68 8b [2] 55 }

  condition:
    any of them
}