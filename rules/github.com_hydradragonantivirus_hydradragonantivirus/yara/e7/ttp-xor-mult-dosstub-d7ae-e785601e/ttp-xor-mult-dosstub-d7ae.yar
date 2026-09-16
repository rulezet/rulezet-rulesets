rule TTP_XOR_MULT_DOSStub_d7ae {
  strings:
    $key_d7ae = { 83 c6 [2] f7 de [2] b0 dc [2] f7 cd [2] b9 c1 [2] b5 cb [2] a2 c0 [2] b9 8e [2] 84 }

  condition:
    any of them
}