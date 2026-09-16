rule TTP_XOR_MULT_DOSStub_9889 {
  strings:
    $key_9889 = { cc e1 [2] b8 f9 [2] ff fb [2] b8 ea [2] f6 e6 [2] fa ec [2] ed e7 [2] f6 a9 [2] cb }

  condition:
    any of them
}