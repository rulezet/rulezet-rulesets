rule TTP_XOR_MULT_DOSStub_9172 {
  strings:
    $key_9172 = { c5 1a [2] b1 02 [2] f6 00 [2] b1 11 [2] ff 1d [2] f3 17 [2] e4 1c [2] ff 52 [2] c2 }

  condition:
    any of them
}