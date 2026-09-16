rule TTP_XOR_MULT_DOSStub_9203 {
  strings:
    $key_9203 = { c6 6b [2] b2 73 [2] f5 71 [2] b2 60 [2] fc 6c [2] f0 66 [2] e7 6d [2] fc 23 [2] c1 }

  condition:
    any of them
}