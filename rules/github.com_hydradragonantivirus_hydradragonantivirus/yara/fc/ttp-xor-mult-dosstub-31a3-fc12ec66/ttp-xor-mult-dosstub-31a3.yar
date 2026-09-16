rule TTP_XOR_MULT_DOSStub_31a3 {
  strings:
    $key_31a3 = { 65 cb [2] 11 d3 [2] 56 d1 [2] 11 c0 [2] 5f cc [2] 53 c6 [2] 44 cd [2] 5f 83 [2] 62 }

  condition:
    any of them
}