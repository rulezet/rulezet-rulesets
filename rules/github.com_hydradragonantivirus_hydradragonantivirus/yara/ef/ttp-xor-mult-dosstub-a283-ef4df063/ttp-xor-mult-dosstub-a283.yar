rule TTP_XOR_MULT_DOSStub_a283 {
  strings:
    $key_a283 = { f6 eb [2] 82 f3 [2] c5 f1 [2] 82 e0 [2] cc ec [2] c0 e6 [2] d7 ed [2] cc a3 [2] f1 }

  condition:
    any of them
}