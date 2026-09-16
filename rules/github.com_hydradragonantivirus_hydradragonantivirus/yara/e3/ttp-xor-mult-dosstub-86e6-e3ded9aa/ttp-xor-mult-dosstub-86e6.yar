rule TTP_XOR_MULT_DOSStub_86e6 {
  strings:
    $key_86e6 = { d2 8e [2] a6 96 [2] e1 94 [2] a6 85 [2] e8 89 [2] e4 83 [2] f3 88 [2] e8 c6 [2] d5 }

  condition:
    any of them
}