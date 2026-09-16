rule TTP_XOR_MULT_DOSStub_a683 {
  strings:
    $key_a683 = { f2 eb [2] 86 f3 [2] c1 f1 [2] 86 e0 [2] c8 ec [2] c4 e6 [2] d3 ed [2] c8 a3 [2] f5 }

  condition:
    any of them
}