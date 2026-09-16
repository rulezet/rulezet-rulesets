rule TTP_XOR_MULT_DOSStub_7fa3 {
  strings:
    $key_7fa3 = { 2b cb [2] 5f d3 [2] 18 d1 [2] 5f c0 [2] 11 cc [2] 1d c6 [2] 0a cd [2] 11 83 [2] 2c }

  condition:
    any of them
}