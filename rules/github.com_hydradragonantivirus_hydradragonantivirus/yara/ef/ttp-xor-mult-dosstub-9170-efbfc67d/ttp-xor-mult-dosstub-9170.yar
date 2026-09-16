rule TTP_XOR_MULT_DOSStub_9170 {
  strings:
    $key_9170 = { c5 18 [2] b1 00 [2] f6 02 [2] b1 13 [2] ff 1f [2] f3 15 [2] e4 1e [2] ff 50 [2] c2 }

  condition:
    any of them
}