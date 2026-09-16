rule TTP_XOR_MULT_DOSStub_9450 {
  strings:
    $key_9450 = { c0 38 [2] b4 20 [2] f3 22 [2] b4 33 [2] fa 3f [2] f6 35 [2] e1 3e [2] fa 70 [2] c7 }

  condition:
    any of them
}