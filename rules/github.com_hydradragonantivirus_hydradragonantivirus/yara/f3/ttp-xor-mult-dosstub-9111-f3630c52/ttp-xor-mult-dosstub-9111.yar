rule TTP_XOR_MULT_DOSStub_9111 {
  strings:
    $key_9111 = { c5 79 [2] b1 61 [2] f6 63 [2] b1 72 [2] ff 7e [2] f3 74 [2] e4 7f [2] ff 31 [2] c2 }

  condition:
    any of them
}