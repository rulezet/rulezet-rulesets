rule TTP_XOR_MULT_DOSStub_9365 {
  strings:
    $key_9365 = { c7 0d [2] b3 15 [2] f4 17 [2] b3 06 [2] fd 0a [2] f1 00 [2] e6 0b [2] fd 45 [2] c0 }

  condition:
    any of them
}