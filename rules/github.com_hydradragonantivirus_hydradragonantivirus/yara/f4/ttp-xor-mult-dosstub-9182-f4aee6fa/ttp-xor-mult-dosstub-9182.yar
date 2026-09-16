rule TTP_XOR_MULT_DOSStub_9182 {
  strings:
    $key_9182 = { c5 ea [2] b1 f2 [2] f6 f0 [2] b1 e1 [2] ff ed [2] f3 e7 [2] e4 ec [2] ff a2 [2] c2 }

  condition:
    any of them
}