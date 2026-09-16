rule TTP_XOR_MULT_DOSStub_9372 {
  strings:
    $key_9372 = { c7 1a [2] b3 02 [2] f4 00 [2] b3 11 [2] fd 1d [2] f1 17 [2] e6 1c [2] fd 52 [2] c0 }

  condition:
    any of them
}