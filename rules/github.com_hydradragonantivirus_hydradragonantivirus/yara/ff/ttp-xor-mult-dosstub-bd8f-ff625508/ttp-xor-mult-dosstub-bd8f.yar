rule TTP_XOR_MULT_DOSStub_bd8f {
  strings:
    $key_bd8f = { e9 e7 [2] 9d ff [2] da fd [2] 9d ec [2] d3 e0 [2] df ea [2] c8 e1 [2] d3 af [2] ee }

  condition:
    any of them
}