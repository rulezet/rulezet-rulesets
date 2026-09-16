rule TTP_XOR_MULT_DOSStub_898f {
  strings:
    $key_898f = { dd e7 [2] a9 ff [2] ee fd [2] a9 ec [2] e7 e0 [2] eb ea [2] fc e1 [2] e7 af [2] da }

  condition:
    any of them
}