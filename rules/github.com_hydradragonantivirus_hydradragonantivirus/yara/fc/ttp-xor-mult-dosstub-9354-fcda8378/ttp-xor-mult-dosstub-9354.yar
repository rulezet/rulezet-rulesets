rule TTP_XOR_MULT_DOSStub_9354 {
  strings:
    $key_9354 = { c7 3c [2] b3 24 [2] f4 26 [2] b3 37 [2] fd 3b [2] f1 31 [2] e6 3a [2] fd 74 [2] c0 }

  condition:
    any of them
}