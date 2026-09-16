rule TTP_XOR_MULT_DOSStub_d3f0 {
  strings:
    $key_d3f0 = { 87 98 [2] f3 80 [2] b4 82 [2] f3 93 [2] bd 9f [2] b1 95 [2] a6 9e [2] bd d0 [2] 80 }

  condition:
    any of them
}