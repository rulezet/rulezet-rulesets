rule TTP_XOR_MULT_DOSStub_9410 {
  strings:
    $key_9410 = { c0 78 [2] b4 60 [2] f3 62 [2] b4 73 [2] fa 7f [2] f6 75 [2] e1 7e [2] fa 30 [2] c7 }

  condition:
    any of them
}