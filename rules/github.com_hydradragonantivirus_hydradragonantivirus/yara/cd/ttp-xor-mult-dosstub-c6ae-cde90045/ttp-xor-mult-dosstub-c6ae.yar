rule TTP_XOR_MULT_DOSStub_c6ae {
  strings:
    $key_c6ae = { 92 c6 [2] e6 de [2] a1 dc [2] e6 cd [2] a8 c1 [2] a4 cb [2] b3 c0 [2] a8 8e [2] 95 }

  condition:
    any of them
}