rule TTP_XOR_MULT_DOSStub_98ca {
  strings:
    $key_98ca = { cc a2 [2] b8 ba [2] ff b8 [2] b8 a9 [2] f6 a5 [2] fa af [2] ed a4 [2] f6 ea [2] cb }

  condition:
    any of them
}