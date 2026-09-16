rule TTP_XOR_MULT_DOSStub_9441 {
  strings:
    $key_9441 = { c0 29 [2] b4 31 [2] f3 33 [2] b4 22 [2] fa 2e [2] f6 24 [2] e1 2f [2] fa 61 [2] c7 }

  condition:
    any of them
}