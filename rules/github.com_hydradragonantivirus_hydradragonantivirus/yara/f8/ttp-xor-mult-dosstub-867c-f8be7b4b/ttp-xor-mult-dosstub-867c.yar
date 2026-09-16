rule TTP_XOR_MULT_DOSStub_867c {
  strings:
    $key_867c = { d2 14 [2] a6 0c [2] e1 0e [2] a6 1f [2] e8 13 [2] e4 19 [2] f3 12 [2] e8 5c [2] d5 }

  condition:
    any of them
}