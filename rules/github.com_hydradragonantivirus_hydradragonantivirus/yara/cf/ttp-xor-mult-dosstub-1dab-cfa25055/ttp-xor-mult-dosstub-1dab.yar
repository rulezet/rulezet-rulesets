rule TTP_XOR_MULT_DOSStub_1dab {
  strings:
    $key_1dab = { 49 c3 [2] 3d db [2] 7a d9 [2] 3d c8 [2] 73 c4 [2] 7f ce [2] 68 c5 [2] 73 8b [2] 4e }

  condition:
    any of them
}