rule TTP_XOR_MULT_DOSStub_9151 {
  strings:
    $key_9151 = { c5 39 [2] b1 21 [2] f6 23 [2] b1 32 [2] ff 3e [2] f3 34 [2] e4 3f [2] ff 71 [2] c2 }

  condition:
    any of them
}