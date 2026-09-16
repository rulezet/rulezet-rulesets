rule TTP_XOR_MULT_DOSStub_a282 {
  strings:
    $key_a282 = { f6 ea [2] 82 f2 [2] c5 f0 [2] 82 e1 [2] cc ed [2] c0 e7 [2] d7 ec [2] cc a2 [2] f1 }

  condition:
    any of them
}