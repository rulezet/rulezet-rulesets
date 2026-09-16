rule TTP_XOR_MULT_DOSStub_9428 {
  strings:
    $key_9428 = { c0 40 [2] b4 58 [2] f3 5a [2] b4 4b [2] fa 47 [2] f6 4d [2] e1 46 [2] fa 08 [2] c7 }

  condition:
    any of them
}