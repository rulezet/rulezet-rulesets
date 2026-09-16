rule TTP_XOR_MULT_DOSStub_9156 {
  strings:
    $key_9156 = { c5 3e [2] b1 26 [2] f6 24 [2] b1 35 [2] ff 39 [2] f3 33 [2] e4 38 [2] ff 76 [2] c2 }

  condition:
    any of them
}