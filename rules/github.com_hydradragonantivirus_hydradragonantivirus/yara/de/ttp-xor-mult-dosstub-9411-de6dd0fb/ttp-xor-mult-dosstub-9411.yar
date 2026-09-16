rule TTP_XOR_MULT_DOSStub_9411 {
  strings:
    $key_9411 = { c0 79 [2] b4 61 [2] f3 63 [2] b4 72 [2] fa 7e [2] f6 74 [2] e1 7f [2] fa 31 [2] c7 }

  condition:
    any of them
}