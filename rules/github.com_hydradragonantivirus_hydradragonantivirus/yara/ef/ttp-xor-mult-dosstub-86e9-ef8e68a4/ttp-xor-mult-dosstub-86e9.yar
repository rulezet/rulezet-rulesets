rule TTP_XOR_MULT_DOSStub_86e9 {
  strings:
    $key_86e9 = { d2 81 [2] a6 99 [2] e1 9b [2] a6 8a [2] e8 86 [2] e4 8c [2] f3 87 [2] e8 c9 [2] d5 }

  condition:
    any of them
}