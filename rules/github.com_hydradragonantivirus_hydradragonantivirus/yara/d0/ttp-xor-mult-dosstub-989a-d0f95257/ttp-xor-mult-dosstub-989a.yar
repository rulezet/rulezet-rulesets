rule TTP_XOR_MULT_DOSStub_989a {
  strings:
    $key_989a = { cc f2 [2] b8 ea [2] ff e8 [2] b8 f9 [2] f6 f5 [2] fa ff [2] ed f4 [2] f6 ba [2] cb }

  condition:
    any of them
}