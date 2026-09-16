rule TTP_XOR_MULT_DOSStub_9b95 {
  strings:
    $key_9b95 = { cf fd [2] bb e5 [2] fc e7 [2] bb f6 [2] f5 fa [2] f9 f0 [2] ee fb [2] f5 b5 [2] c8 }

  condition:
    any of them
}