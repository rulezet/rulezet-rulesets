rule TTP_XOR_MULT_DOSStub_86a4 {
  strings:
    $key_86a4 = { d2 cc [2] a6 d4 [2] e1 d6 [2] a6 c7 [2] e8 cb [2] e4 c1 [2] f3 ca [2] e8 84 [2] d5 }

  condition:
    any of them
}