rule TTP_XOR_MULT_DOSStub_4fa3 {
  strings:
    $key_4fa3 = { 1b cb [2] 6f d3 [2] 28 d1 [2] 6f c0 [2] 21 cc [2] 2d c6 [2] 3a cd [2] 21 83 [2] 1c }

  condition:
    any of them
}