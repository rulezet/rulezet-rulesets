rule TTP_XOR_MULT_DOSStub_898d {
  strings:
    $key_898d = { dd e5 [2] a9 fd [2] ee ff [2] a9 ee [2] e7 e2 [2] eb e8 [2] fc e3 [2] e7 ad [2] da }

  condition:
    any of them
}