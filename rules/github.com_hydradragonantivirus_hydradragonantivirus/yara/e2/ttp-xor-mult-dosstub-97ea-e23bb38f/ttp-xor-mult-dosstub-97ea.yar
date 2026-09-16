rule TTP_XOR_MULT_DOSStub_97ea {
  strings:
    $key_97ea = { c3 82 [2] b7 9a [2] f0 98 [2] b7 89 [2] f9 85 [2] f5 8f [2] e2 84 [2] f9 ca [2] c4 }

  condition:
    any of them
}