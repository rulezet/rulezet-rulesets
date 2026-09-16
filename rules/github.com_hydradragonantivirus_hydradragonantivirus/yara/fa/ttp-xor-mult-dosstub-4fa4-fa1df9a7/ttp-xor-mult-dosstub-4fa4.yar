rule TTP_XOR_MULT_DOSStub_4fa4 {
  strings:
    $key_4fa4 = { 1b cc [2] 6f d4 [2] 28 d6 [2] 6f c7 [2] 21 cb [2] 2d c1 [2] 3a ca [2] 21 84 [2] 1c }

  condition:
    any of them
}