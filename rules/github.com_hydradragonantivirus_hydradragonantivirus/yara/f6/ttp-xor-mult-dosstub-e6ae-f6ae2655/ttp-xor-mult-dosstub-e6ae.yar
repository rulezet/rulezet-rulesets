rule TTP_XOR_MULT_DOSStub_e6ae {
  strings:
    $key_e6ae = { b2 c6 [2] c6 de [2] 81 dc [2] c6 cd [2] 88 c1 [2] 84 cb [2] 93 c0 [2] 88 8e [2] b5 }

  condition:
    any of them
}