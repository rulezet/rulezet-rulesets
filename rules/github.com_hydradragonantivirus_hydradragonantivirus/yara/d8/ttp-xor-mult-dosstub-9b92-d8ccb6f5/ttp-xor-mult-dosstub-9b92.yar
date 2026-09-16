rule TTP_XOR_MULT_DOSStub_9b92 {
  strings:
    $key_9b92 = { cf fa [2] bb e2 [2] fc e0 [2] bb f1 [2] f5 fd [2] f9 f7 [2] ee fc [2] f5 b2 [2] c8 }

  condition:
    any of them
}