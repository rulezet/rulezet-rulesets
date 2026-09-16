rule TTP_XOR_MULT_DOSStub_8382 {
  strings:
    $key_8382 = { d7 ea [2] a3 f2 [2] e4 f0 [2] a3 e1 [2] ed ed [2] e1 e7 [2] f6 ec [2] ed a2 [2] d0 }

  condition:
    any of them
}