rule TTP_XOR_MULT_DOSStub_36a3 {
  strings:
    $key_36a3 = { 62 cb [2] 16 d3 [2] 51 d1 [2] 16 c0 [2] 58 cc [2] 54 c6 [2] 43 cd [2] 58 83 [2] 65 }

  condition:
    any of them
}