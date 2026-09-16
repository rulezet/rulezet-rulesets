rule TTP_XOR_MULT_DOSStub_94e6 {
  strings:
    $key_94e6 = { c0 8e [2] b4 96 [2] f3 94 [2] b4 85 [2] fa 89 [2] f6 83 [2] e1 88 [2] fa c6 [2] c7 }

  condition:
    any of them
}