rule TTP_XOR_MULT_DOSStub_97eb {
  strings:
    $key_97eb = { c3 83 [2] b7 9b [2] f0 99 [2] b7 88 [2] f9 84 [2] f5 8e [2] e2 85 [2] f9 cb [2] c4 }

  condition:
    any of them
}