rule TTP_XOR_MULT_DOSStub_9bd3 {
  strings:
    $key_9bd3 = { cf bb [2] bb a3 [2] fc a1 [2] bb b0 [2] f5 bc [2] f9 b6 [2] ee bd [2] f5 f3 [2] c8 }

  condition:
    any of them
}