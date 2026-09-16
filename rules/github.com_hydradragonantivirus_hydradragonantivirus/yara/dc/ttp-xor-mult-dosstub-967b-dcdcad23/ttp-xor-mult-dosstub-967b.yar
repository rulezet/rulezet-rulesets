rule TTP_XOR_MULT_DOSStub_967b {
  strings:
    $key_967b = { c2 13 [2] b6 0b [2] f1 09 [2] b6 18 [2] f8 14 [2] f4 1e [2] e3 15 [2] f8 5b [2] c5 }

  condition:
    any of them
}