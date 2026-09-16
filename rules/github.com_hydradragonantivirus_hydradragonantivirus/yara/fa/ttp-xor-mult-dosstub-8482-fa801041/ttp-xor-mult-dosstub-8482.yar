rule TTP_XOR_MULT_DOSStub_8482 {
  strings:
    $key_8482 = { d0 ea [2] a4 f2 [2] e3 f0 [2] a4 e1 [2] ea ed [2] e6 e7 [2] f1 ec [2] ea a2 [2] d7 }

  condition:
    any of them
}