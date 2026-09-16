rule TTP_XOR_MULT_DOSStub_96fa {
  strings:
    $key_96fa = { c2 92 [2] b6 8a [2] f1 88 [2] b6 99 [2] f8 95 [2] f4 9f [2] e3 94 [2] f8 da [2] c5 }

  condition:
    any of them
}