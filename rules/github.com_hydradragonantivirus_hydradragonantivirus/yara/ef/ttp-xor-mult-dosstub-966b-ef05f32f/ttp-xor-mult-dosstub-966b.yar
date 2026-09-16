rule TTP_XOR_MULT_DOSStub_966b {
  strings:
    $key_966b = { c2 03 [2] b6 1b [2] f1 19 [2] b6 08 [2] f8 04 [2] f4 0e [2] e3 05 [2] f8 4b [2] c5 }

  condition:
    any of them
}