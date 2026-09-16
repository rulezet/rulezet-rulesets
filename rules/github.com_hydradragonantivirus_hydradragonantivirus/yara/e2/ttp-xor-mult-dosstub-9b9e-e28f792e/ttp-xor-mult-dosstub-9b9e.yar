rule TTP_XOR_MULT_DOSStub_9b9e {
  strings:
    $key_9b9e = { cf f6 [2] bb ee [2] fc ec [2] bb fd [2] f5 f1 [2] f9 fb [2] ee f0 [2] f5 be [2] c8 }

  condition:
    any of them
}