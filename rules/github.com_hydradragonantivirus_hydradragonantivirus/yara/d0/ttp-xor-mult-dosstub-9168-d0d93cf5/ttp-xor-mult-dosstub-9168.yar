rule TTP_XOR_MULT_DOSStub_9168 {
  strings:
    $key_9168 = { c5 00 [2] b1 18 [2] f6 1a [2] b1 0b [2] ff 07 [2] f3 0d [2] e4 06 [2] ff 48 [2] c2 }

  condition:
    any of them
}