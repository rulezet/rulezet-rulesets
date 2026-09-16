rule TTP_XOR_MULT_DOSStub_9183 {
  strings:
    $key_9183 = { c5 eb [2] b1 f3 [2] f6 f1 [2] b1 e0 [2] ff ec [2] f3 e6 [2] e4 ed [2] ff a3 [2] c2 }

  condition:
    any of them
}