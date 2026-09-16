rule TTP_XOR_MULT_DOSStub_7ea6 {
  strings:
    $key_7ea6 = { 2a ce [2] 5e d6 [2] 19 d4 [2] 5e c5 [2] 10 c9 [2] 1c c3 [2] 0b c8 [2] 10 86 [2] 2d }

  condition:
    any of them
}