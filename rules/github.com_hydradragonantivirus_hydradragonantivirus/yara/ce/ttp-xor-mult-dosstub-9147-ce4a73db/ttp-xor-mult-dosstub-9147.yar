rule TTP_XOR_MULT_DOSStub_9147 {
  strings:
    $key_9147 = { c5 2f [2] b1 37 [2] f6 35 [2] b1 24 [2] ff 28 [2] f3 22 [2] e4 29 [2] ff 67 [2] c2 }

  condition:
    any of them
}