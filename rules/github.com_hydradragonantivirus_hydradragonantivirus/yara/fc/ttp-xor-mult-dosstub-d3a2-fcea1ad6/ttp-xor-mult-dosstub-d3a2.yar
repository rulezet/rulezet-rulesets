rule TTP_XOR_MULT_DOSStub_d3a2 {
  strings:
    $key_d3a2 = { 87 ca [2] f3 d2 [2] b4 d0 [2] f3 c1 [2] bd cd [2] b1 c7 [2] a6 cc [2] bd 82 [2] 80 }

  condition:
    any of them
}