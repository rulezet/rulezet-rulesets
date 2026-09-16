rule TTP_XOR_MULT_DOSStub_86b5 {
  strings:
    $key_86b5 = { d2 dd [2] a6 c5 [2] e1 c7 [2] a6 d6 [2] e8 da [2] e4 d0 [2] f3 db [2] e8 95 [2] d5 }

  condition:
    any of them
}