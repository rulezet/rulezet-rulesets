rule TTP_XOR_MULT_DOSStub_22a3 {
  strings:
    $key_22a3 = { 76 cb [2] 02 d3 [2] 45 d1 [2] 02 c0 [2] 4c cc [2] 40 c6 [2] 57 cd [2] 4c 83 [2] 71 }

  condition:
    any of them
}