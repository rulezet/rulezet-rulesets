rule TTP_XOR_MULT_DOSStub_86a9 {
  strings:
    $key_86a9 = { d2 c1 [2] a6 d9 [2] e1 db [2] a6 ca [2] e8 c6 [2] e4 cc [2] f3 c7 [2] e8 89 [2] d5 }

  condition:
    any of them
}