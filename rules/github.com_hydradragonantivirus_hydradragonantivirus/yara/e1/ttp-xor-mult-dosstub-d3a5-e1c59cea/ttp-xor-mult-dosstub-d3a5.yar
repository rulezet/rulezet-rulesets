rule TTP_XOR_MULT_DOSStub_d3a5 {
  strings:
    $key_d3a5 = { 87 cd [2] f3 d5 [2] b4 d7 [2] f3 c6 [2] bd ca [2] b1 c0 [2] a6 cb [2] bd 85 [2] 80 }

  condition:
    any of them
}