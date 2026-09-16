rule TTP_XOR_MULT_DOSStub_85ae {
  strings:
    $key_85ae = { d1 c6 [2] a5 de [2] e2 dc [2] a5 cd [2] eb c1 [2] e7 cb [2] f0 c0 [2] eb 8e [2] d6 }

  condition:
    any of them
}