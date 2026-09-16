rule TTP_XOR_MULT_DOSStub_8687 {
  strings:
    $key_8687 = { d2 ef [2] a6 f7 [2] e1 f5 [2] a6 e4 [2] e8 e8 [2] e4 e2 [2] f3 e9 [2] e8 a7 [2] d5 }

  condition:
    any of them
}