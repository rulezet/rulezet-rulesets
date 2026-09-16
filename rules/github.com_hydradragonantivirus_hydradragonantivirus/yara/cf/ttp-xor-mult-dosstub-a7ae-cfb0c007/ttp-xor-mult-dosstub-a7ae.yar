rule TTP_XOR_MULT_DOSStub_a7ae {
  strings:
    $key_a7ae = { f3 c6 [2] 87 de [2] c0 dc [2] 87 cd [2] c9 c1 [2] c5 cb [2] d2 c0 [2] c9 8e [2] f4 }

  condition:
    any of them
}