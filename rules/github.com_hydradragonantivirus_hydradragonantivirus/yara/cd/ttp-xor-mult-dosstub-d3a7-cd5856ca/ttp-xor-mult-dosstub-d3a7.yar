rule TTP_XOR_MULT_DOSStub_d3a7 {
  strings:
    $key_d3a7 = { 87 cf [2] f3 d7 [2] b4 d5 [2] f3 c4 [2] bd c8 [2] b1 c2 [2] a6 c9 [2] bd 87 [2] 80 }

  condition:
    any of them
}