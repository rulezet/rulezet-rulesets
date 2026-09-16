rule TTP_XOR_MULT_DOSStub_9573 {
  strings:
    $key_9573 = { c1 1b [2] b5 03 [2] f2 01 [2] b5 10 [2] fb 1c [2] f7 16 [2] e0 1d [2] fb 53 [2] c6 }

  condition:
    any of them
}