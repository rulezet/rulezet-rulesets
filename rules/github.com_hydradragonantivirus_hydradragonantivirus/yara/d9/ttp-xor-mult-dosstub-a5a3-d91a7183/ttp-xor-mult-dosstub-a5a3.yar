rule TTP_XOR_MULT_DOSStub_a5a3 {
  strings:
    $key_a5a3 = { f1 cb [2] 85 d3 [2] c2 d1 [2] 85 c0 [2] cb cc [2] c7 c6 [2] d0 cd [2] cb 83 [2] f6 }

  condition:
    any of them
}