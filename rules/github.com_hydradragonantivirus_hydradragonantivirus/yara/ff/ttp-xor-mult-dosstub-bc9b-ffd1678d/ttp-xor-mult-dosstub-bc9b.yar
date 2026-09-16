rule TTP_XOR_MULT_DOSStub_bc9b {
  strings:
    $key_bc9b = { e8 f3 [2] 9c eb [2] db e9 [2] 9c f8 [2] d2 f4 [2] de fe [2] c9 f5 [2] d2 bb [2] ef }

  condition:
    any of them
}