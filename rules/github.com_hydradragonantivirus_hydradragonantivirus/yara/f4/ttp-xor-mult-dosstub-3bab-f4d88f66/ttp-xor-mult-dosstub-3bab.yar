rule TTP_XOR_MULT_DOSStub_3bab {
  strings:
    $key_3bab = { 6f c3 [2] 1b db [2] 5c d9 [2] 1b c8 [2] 55 c4 [2] 59 ce [2] 4e c5 [2] 55 8b [2] 68 }

  condition:
    any of them
}