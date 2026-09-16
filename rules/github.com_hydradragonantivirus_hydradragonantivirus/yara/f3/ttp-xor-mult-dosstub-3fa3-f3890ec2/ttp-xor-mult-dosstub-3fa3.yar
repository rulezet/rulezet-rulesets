rule TTP_XOR_MULT_DOSStub_3fa3 {
  strings:
    $key_3fa3 = { 6b cb [2] 1f d3 [2] 58 d1 [2] 1f c0 [2] 51 cc [2] 5d c6 [2] 4a cd [2] 51 83 [2] 6c }

  condition:
    any of them
}