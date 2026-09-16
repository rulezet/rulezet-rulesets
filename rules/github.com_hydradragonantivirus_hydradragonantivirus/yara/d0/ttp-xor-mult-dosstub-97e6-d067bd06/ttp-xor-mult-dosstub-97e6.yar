rule TTP_XOR_MULT_DOSStub_97e6 {
  strings:
    $key_97e6 = { c3 8e [2] b7 96 [2] f0 94 [2] b7 85 [2] f9 89 [2] f5 83 [2] e2 88 [2] f9 c6 [2] c4 }

  condition:
    any of them
}