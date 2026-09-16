rule TTP_XOR_MULT_DOSStub_9630 {
  strings:
    $key_9630 = { c2 58 [2] b6 40 [2] f1 42 [2] b6 53 [2] f8 5f [2] f4 55 [2] e3 5e [2] f8 10 [2] c5 }

  condition:
    any of them
}