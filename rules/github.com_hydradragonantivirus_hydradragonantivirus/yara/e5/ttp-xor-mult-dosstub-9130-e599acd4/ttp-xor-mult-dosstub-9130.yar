rule TTP_XOR_MULT_DOSStub_9130 {
  strings:
    $key_9130 = { c5 58 [2] b1 40 [2] f6 42 [2] b1 53 [2] ff 5f [2] f3 55 [2] e4 5e [2] ff 10 [2] c2 }

  condition:
    any of them
}