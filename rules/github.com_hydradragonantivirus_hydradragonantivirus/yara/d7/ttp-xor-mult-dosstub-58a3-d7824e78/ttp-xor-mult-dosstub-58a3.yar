rule TTP_XOR_MULT_DOSStub_58a3 {
  strings:
    $key_58a3 = { 0c cb [2] 78 d3 [2] 3f d1 [2] 78 c0 [2] 36 cc [2] 3a c6 [2] 2d cd [2] 36 83 [2] 0b }

  condition:
    any of them
}