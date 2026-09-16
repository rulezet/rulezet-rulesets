rule TTP_XOR_MULT_DOSStub_d3ae {
  strings:
    $key_d3ae = { 87 c6 [2] f3 de [2] b4 dc [2] f3 cd [2] bd c1 [2] b1 cb [2] a6 c0 [2] bd 8e [2] 80 }

  condition:
    any of them
}