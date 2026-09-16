rule TTP_XOR_MULT_DOSStub_9141 {
  strings:
    $key_9141 = { c5 29 [2] b1 31 [2] f6 33 [2] b1 22 [2] ff 2e [2] f3 24 [2] e4 2f [2] ff 61 [2] c2 }

  condition:
    any of them
}