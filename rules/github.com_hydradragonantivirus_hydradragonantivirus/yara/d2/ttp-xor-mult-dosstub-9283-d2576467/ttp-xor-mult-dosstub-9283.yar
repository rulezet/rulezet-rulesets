rule TTP_XOR_MULT_DOSStub_9283 {
  strings:
    $key_9283 = { c6 eb [2] b2 f3 [2] f5 f1 [2] b2 e0 [2] fc ec [2] f0 e6 [2] e7 ed [2] fc a3 [2] c1 }

  condition:
    any of them
}