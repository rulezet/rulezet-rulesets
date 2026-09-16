rule TTP_XOR_MULT_DOSStub_8282 {
  strings:
    $key_8282 = { d6 ea [2] a2 f2 [2] e5 f0 [2] a2 e1 [2] ec ed [2] e0 e7 [2] f7 ec [2] ec a2 [2] d1 }

  condition:
    any of them
}