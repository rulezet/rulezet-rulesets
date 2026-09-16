rule TTP_XOR_MULT_DOSStub_9bad {
  strings:
    $key_9bad = { cf c5 [2] bb dd [2] fc df [2] bb ce [2] f5 c2 [2] f9 c8 [2] ee c3 [2] f5 8d [2] c8 }

  condition:
    any of them
}