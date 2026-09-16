rule TTP_XOR_MULT_DOSStub_9378 {
  strings:
    $key_9378 = { c7 10 [2] b3 08 [2] f4 0a [2] b3 1b [2] fd 17 [2] f1 1d [2] e6 16 [2] fd 58 [2] c0 }

  condition:
    any of them
}