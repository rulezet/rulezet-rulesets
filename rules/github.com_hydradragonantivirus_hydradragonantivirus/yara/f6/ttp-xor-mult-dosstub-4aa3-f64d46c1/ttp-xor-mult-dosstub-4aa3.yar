rule TTP_XOR_MULT_DOSStub_4aa3 {
  strings:
    $key_4aa3 = { 1e cb [2] 6a d3 [2] 2d d1 [2] 6a c0 [2] 24 cc [2] 28 c6 [2] 3f cd [2] 24 83 [2] 19 }

  condition:
    any of them
}