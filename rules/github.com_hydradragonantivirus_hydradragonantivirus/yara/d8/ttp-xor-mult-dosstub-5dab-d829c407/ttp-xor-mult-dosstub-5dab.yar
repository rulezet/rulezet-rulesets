rule TTP_XOR_MULT_DOSStub_5dab {
  strings:
    $key_5dab = { 09 c3 [2] 7d db [2] 3a d9 [2] 7d c8 [2] 33 c4 [2] 3f ce [2] 28 c5 [2] 33 8b [2] 0e }

  condition:
    any of them
}