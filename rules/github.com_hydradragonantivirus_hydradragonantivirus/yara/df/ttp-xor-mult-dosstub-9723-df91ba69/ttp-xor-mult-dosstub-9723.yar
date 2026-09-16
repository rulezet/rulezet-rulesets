rule TTP_XOR_MULT_DOSStub_9723 {
  strings:
    $key_9723 = { c3 4b [2] b7 53 [2] f0 51 [2] b7 40 [2] f9 4c [2] f5 46 [2] e2 4d [2] f9 03 [2] c4 }

  condition:
    any of them
}