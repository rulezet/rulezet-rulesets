rule TTP_XOR_MULT_DOSStub_01a3 {
  strings:
    $key_01a3 = { 55 cb [2] 21 d3 [2] 66 d1 [2] 21 c0 [2] 6f cc [2] 63 c6 [2] 74 cd [2] 6f 83 [2] 52 }

  condition:
    any of them
}