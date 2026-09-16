rule TTP_XOR_MULT_DOSStub_54a3 {
  strings:
    $key_54a3 = { 00 cb [2] 74 d3 [2] 33 d1 [2] 74 c0 [2] 3a cc [2] 36 c6 [2] 21 cd [2] 3a 83 [2] 07 }

  condition:
    any of them
}