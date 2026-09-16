rule TTP_XOR_MULT_DOSStub_9333 {
  strings:
    $key_9333 = { c7 5b [2] b3 43 [2] f4 41 [2] b3 50 [2] fd 5c [2] f1 56 [2] e6 5d [2] fd 13 [2] c0 }

  condition:
    any of them
}