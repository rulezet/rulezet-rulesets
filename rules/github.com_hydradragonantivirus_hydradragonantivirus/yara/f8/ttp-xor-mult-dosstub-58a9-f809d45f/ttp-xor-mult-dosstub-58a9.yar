rule TTP_XOR_MULT_DOSStub_58a9 {
  strings:
    $key_58a9 = { 0c c1 [2] 78 d9 [2] 3f db [2] 78 ca [2] 36 c6 [2] 3a cc [2] 2d c7 [2] 36 89 [2] 0b }

  condition:
    any of them
}