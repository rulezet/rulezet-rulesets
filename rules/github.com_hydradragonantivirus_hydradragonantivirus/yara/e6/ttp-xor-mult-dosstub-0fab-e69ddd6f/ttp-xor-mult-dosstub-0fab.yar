rule TTP_XOR_MULT_DOSStub_0fab {
  strings:
    $key_0fab = { 5b c3 [2] 2f db [2] 68 d9 [2] 2f c8 [2] 61 c4 [2] 6d ce [2] 7a c5 [2] 61 8b [2] 5c }

  condition:
    any of them
}