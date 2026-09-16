rule TTP_XOR_MULT_DOSStub_27a3 {
  strings:
    $key_27a3 = { 73 cb [2] 07 d3 [2] 40 d1 [2] 07 c0 [2] 49 cc [2] 45 c6 [2] 52 cd [2] 49 83 [2] 74 }

  condition:
    any of them
}