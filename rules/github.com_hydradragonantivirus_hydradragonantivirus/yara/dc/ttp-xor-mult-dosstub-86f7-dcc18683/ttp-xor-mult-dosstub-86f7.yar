rule TTP_XOR_MULT_DOSStub_86f7 {
  strings:
    $key_86f7 = { d2 9f [2] a6 87 [2] e1 85 [2] a6 94 [2] e8 98 [2] e4 92 [2] f3 99 [2] e8 d7 [2] d5 }

  condition:
    any of them
}