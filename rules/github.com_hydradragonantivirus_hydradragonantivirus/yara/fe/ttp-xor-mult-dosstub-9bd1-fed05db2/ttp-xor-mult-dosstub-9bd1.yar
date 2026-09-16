rule TTP_XOR_MULT_DOSStub_9bd1 {
  strings:
    $key_9bd1 = { cf b9 [2] bb a1 [2] fc a3 [2] bb b2 [2] f5 be [2] f9 b4 [2] ee bf [2] f5 f1 [2] c8 }

  condition:
    any of them
}