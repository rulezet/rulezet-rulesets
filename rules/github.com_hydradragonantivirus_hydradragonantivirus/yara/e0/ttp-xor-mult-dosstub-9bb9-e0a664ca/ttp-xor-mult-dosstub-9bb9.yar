rule TTP_XOR_MULT_DOSStub_9bb9 {
  strings:
    $key_9bb9 = { cf d1 [2] bb c9 [2] fc cb [2] bb da [2] f5 d6 [2] f9 dc [2] ee d7 [2] f5 99 [2] c8 }

  condition:
    any of them
}