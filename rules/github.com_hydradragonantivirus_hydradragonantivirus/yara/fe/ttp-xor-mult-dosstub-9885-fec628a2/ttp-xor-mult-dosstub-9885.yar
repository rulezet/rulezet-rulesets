rule TTP_XOR_MULT_DOSStub_9885 {
  strings:
    $key_9885 = { cc ed [2] b8 f5 [2] ff f7 [2] b8 e6 [2] f6 ea [2] fa e0 [2] ed eb [2] f6 a5 [2] cb }

  condition:
    any of them
}