rule TTP_XOR_MULT_DOSStub_92ac {
  strings:
    $key_92ac = { c6 c4 [2] b2 dc [2] f5 de [2] b2 cf [2] fc c3 [2] f0 c9 [2] e7 c2 [2] fc 8c [2] c1 }

  condition:
    any of them
}