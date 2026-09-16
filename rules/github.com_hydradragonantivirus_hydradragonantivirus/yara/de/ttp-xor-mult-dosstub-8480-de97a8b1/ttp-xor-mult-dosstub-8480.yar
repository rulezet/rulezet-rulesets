rule TTP_XOR_MULT_DOSStub_8480 {
  strings:
    $key_8480 = { d0 e8 [2] a4 f0 [2] e3 f2 [2] a4 e3 [2] ea ef [2] e6 e5 [2] f1 ee [2] ea a0 [2] d7 }

  condition:
    any of them
}