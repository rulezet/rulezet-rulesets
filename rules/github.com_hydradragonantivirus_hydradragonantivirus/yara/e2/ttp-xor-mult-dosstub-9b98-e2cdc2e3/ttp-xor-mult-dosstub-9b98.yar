rule TTP_XOR_MULT_DOSStub_9b98 {
  strings:
    $key_9b98 = { cf f0 [2] bb e8 [2] fc ea [2] bb fb [2] f5 f7 [2] f9 fd [2] ee f6 [2] f5 b8 [2] c8 }

  condition:
    any of them
}