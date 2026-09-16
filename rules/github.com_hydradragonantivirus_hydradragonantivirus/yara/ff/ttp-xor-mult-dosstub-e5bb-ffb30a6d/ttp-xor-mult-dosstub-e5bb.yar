rule TTP_XOR_MULT_DOSStub_e5bb {
  strings:
    $key_e5bb = { b1 d3 [2] c5 cb [2] 82 c9 [2] c5 d8 [2] 8b d4 [2] 87 de [2] 90 d5 [2] 8b 9b [2] b6 }

  condition:
    any of them
}