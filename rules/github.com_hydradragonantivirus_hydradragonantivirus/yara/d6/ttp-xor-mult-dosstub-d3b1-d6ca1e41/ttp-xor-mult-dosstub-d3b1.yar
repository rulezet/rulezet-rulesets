rule TTP_XOR_MULT_DOSStub_d3b1 {
  strings:
    $key_d3b1 = { 87 d9 [2] f3 c1 [2] b4 c3 [2] f3 d2 [2] bd de [2] b1 d4 [2] a6 df [2] bd 91 [2] 80 }

  condition:
    any of them
}