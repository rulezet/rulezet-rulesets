rule TTP_XOR_MULT_DOSStub_5c9b {
  strings:
    $key_5c9b = { 08 f3 [2] 7c eb [2] 3b e9 [2] 7c f8 [2] 32 f4 [2] 3e fe [2] 29 f5 [2] 32 bb [2] 0f }

  condition:
    any of them
}