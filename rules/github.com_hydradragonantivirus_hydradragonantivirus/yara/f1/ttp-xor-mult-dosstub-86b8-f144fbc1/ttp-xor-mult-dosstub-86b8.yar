rule TTP_XOR_MULT_DOSStub_86b8 {
  strings:
    $key_86b8 = { d2 d0 [2] a6 c8 [2] e1 ca [2] a6 db [2] e8 d7 [2] e4 dd [2] f3 d6 [2] e8 98 [2] d5 }

  condition:
    any of them
}