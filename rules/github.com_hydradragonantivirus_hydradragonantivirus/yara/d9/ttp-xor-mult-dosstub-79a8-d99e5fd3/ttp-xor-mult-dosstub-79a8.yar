rule TTP_XOR_MULT_DOSStub_79a8 {
  strings:
    $key_79a8 = { 2d c0 [2] 59 d8 [2] 1e da [2] 59 cb [2] 17 c7 [2] 1b cd [2] 0c c6 [2] 17 88 [2] 2a }

  condition:
    any of them
}