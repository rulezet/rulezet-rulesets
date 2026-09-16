rule TTP_XOR_MULT_DOSStub_9406 {
  strings:
    $key_9406 = { c0 6e [2] b4 76 [2] f3 74 [2] b4 65 [2] fa 69 [2] f6 63 [2] e1 68 [2] fa 26 [2] c7 }

  condition:
    any of them
}