rule TTP_XOR_MULT_DOSStub_86f5 {
  strings:
    $key_86f5 = { d2 9d [2] a6 85 [2] e1 87 [2] a6 96 [2] e8 9a [2] e4 90 [2] f3 9b [2] e8 d5 [2] d5 }

  condition:
    any of them
}