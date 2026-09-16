rule TTP_XOR_MULT_DOSStub_9673 {
  strings:
    $key_9673 = { c2 1b [2] b6 03 [2] f1 01 [2] b6 10 [2] f8 1c [2] f4 16 [2] e3 1d [2] f8 53 [2] c5 }

  condition:
    any of them
}