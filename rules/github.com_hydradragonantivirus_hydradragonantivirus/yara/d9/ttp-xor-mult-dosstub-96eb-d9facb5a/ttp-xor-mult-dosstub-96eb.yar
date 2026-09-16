rule TTP_XOR_MULT_DOSStub_96eb {
  strings:
    $key_96eb = { c2 83 [2] b6 9b [2] f1 99 [2] b6 88 [2] f8 84 [2] f4 8e [2] e3 85 [2] f8 cb [2] c5 }

  condition:
    any of them
}