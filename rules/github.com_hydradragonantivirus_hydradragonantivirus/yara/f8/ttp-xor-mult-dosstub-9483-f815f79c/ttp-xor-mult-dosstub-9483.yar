rule TTP_XOR_MULT_DOSStub_9483 {
  strings:
    $key_9483 = { c0 eb [2] b4 f3 [2] f3 f1 [2] b4 e0 [2] fa ec [2] f6 e6 [2] e1 ed [2] fa a3 [2] c7 }

  condition:
    any of them
}