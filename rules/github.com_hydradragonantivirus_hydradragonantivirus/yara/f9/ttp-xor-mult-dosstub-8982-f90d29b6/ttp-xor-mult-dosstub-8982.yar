rule TTP_XOR_MULT_DOSStub_8982 {
  strings:
    $key_8982 = { dd ea [2] a9 f2 [2] ee f0 [2] a9 e1 [2] e7 ed [2] eb e7 [2] fc ec [2] e7 a2 [2] da }

  condition:
    any of them
}