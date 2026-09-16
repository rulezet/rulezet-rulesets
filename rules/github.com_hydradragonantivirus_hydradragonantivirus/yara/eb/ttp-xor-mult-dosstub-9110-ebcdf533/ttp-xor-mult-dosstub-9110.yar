rule TTP_XOR_MULT_DOSStub_9110 {
  strings:
    $key_9110 = { c5 78 [2] b1 60 [2] f6 62 [2] b1 73 [2] ff 7f [2] f3 75 [2] e4 7e [2] ff 30 [2] c2 }

  condition:
    any of them
}