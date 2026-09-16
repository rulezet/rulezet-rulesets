rule TTP_XOR_MULT_DOSStub_63a3 {
  strings:
    $key_63a3 = { 37 cb [2] 43 d3 [2] 04 d1 [2] 43 c0 [2] 0d cc [2] 01 c6 [2] 16 cd [2] 0d 83 [2] 30 }

  condition:
    any of them
}