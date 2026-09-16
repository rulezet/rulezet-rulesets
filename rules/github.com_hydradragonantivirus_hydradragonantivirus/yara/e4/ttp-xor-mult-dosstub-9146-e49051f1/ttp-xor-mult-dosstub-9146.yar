rule TTP_XOR_MULT_DOSStub_9146 {
  strings:
    $key_9146 = { c5 2e [2] b1 36 [2] f6 34 [2] b1 25 [2] ff 29 [2] f3 23 [2] e4 28 [2] ff 66 [2] c2 }

  condition:
    any of them
}