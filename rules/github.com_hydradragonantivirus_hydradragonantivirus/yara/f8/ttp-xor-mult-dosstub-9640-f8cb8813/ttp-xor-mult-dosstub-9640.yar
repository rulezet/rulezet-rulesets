rule TTP_XOR_MULT_DOSStub_9640 {
  strings:
    $key_9640 = { c2 28 [2] b6 30 [2] f1 32 [2] b6 23 [2] f8 2f [2] f4 25 [2] e3 2e [2] f8 60 [2] c5 }

  condition:
    any of them
}