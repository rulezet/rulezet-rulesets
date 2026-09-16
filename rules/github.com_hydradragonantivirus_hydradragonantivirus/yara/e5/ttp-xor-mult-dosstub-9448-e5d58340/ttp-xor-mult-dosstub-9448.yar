rule TTP_XOR_MULT_DOSStub_9448 {
  strings:
    $key_9448 = { c0 20 [2] b4 38 [2] f3 3a [2] b4 2b [2] fa 27 [2] f6 2d [2] e1 26 [2] fa 68 [2] c7 }

  condition:
    any of them
}