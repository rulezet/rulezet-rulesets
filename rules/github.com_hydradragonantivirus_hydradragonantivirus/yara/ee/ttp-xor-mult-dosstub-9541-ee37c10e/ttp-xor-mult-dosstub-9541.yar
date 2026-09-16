rule TTP_XOR_MULT_DOSStub_9541 {
  strings:
    $key_9541 = { c1 29 [2] b5 31 [2] f2 33 [2] b5 22 [2] fb 2e [2] f7 24 [2] e0 2f [2] fb 61 [2] c6 }

  condition:
    any of them
}