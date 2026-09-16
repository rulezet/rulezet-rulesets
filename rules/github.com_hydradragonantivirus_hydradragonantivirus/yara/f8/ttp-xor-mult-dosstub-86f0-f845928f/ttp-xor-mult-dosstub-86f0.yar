rule TTP_XOR_MULT_DOSStub_86f0 {
  strings:
    $key_86f0 = { d2 98 [2] a6 80 [2] e1 82 [2] a6 93 [2] e8 9f [2] e4 95 [2] f3 9e [2] e8 d0 [2] d5 }

  condition:
    any of them
}