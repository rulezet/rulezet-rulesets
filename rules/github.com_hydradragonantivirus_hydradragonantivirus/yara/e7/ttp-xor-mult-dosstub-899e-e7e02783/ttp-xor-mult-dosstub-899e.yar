rule TTP_XOR_MULT_DOSStub_899e {
  strings:
    $key_899e = { dd f6 [2] a9 ee [2] ee ec [2] a9 fd [2] e7 f1 [2] eb fb [2] fc f0 [2] e7 be [2] da }

  condition:
    any of them
}