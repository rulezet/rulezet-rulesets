rule TTP_XOR_MULT_DOSStub_d3b9 {
  strings:
    $key_d3b9 = { 87 d1 [2] f3 c9 [2] b4 cb [2] f3 da [2] bd d6 [2] b1 dc [2] a6 d7 [2] bd 99 [2] 80 }

  condition:
    any of them
}