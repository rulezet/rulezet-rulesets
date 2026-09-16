rule TTP_XOR_MULT_DOSStub_a7a3 {
  strings:
    $key_a7a3 = { f3 cb [2] 87 d3 [2] c0 d1 [2] 87 c0 [2] c9 cc [2] c5 c6 [2] d2 cd [2] c9 83 [2] f4 }

  condition:
    any of them
}