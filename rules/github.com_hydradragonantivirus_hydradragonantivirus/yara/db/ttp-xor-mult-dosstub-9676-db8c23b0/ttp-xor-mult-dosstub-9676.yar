rule TTP_XOR_MULT_DOSStub_9676 {
  strings:
    $key_9676 = { c2 1e [2] b6 06 [2] f1 04 [2] b6 15 [2] f8 19 [2] f4 13 [2] e3 18 [2] f8 56 [2] c5 }

  condition:
    any of them
}