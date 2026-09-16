rule TTP_XOR_MULT_DOSStub_2dab {
  strings:
    $key_2dab = { 79 c3 [2] 0d db [2] 4a d9 [2] 0d c8 [2] 43 c4 [2] 4f ce [2] 58 c5 [2] 43 8b [2] 7e }

  condition:
    any of them
}