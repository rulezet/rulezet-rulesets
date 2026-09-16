rule TTP_XOR_MULT_DOSStub_3c9b {
  strings:
    $key_3c9b = { 68 f3 [2] 1c eb [2] 5b e9 [2] 1c f8 [2] 52 f4 [2] 5e fe [2] 49 f5 [2] 52 bb [2] 6f }

  condition:
    any of them
}