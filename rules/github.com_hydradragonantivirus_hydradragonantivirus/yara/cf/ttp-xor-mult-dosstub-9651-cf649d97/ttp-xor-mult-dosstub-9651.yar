rule TTP_XOR_MULT_DOSStub_9651 {
  strings:
    $key_9651 = { c2 39 [2] b6 21 [2] f1 23 [2] b6 32 [2] f8 3e [2] f4 34 [2] e3 3f [2] f8 71 [2] c5 }

  condition:
    any of them
}