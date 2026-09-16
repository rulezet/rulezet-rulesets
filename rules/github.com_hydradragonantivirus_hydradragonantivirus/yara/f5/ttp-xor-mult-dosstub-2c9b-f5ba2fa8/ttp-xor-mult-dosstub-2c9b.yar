rule TTP_XOR_MULT_DOSStub_2c9b {
  strings:
    $key_2c9b = { 78 f3 [2] 0c eb [2] 4b e9 [2] 0c f8 [2] 42 f4 [2] 4e fe [2] 59 f5 [2] 42 bb [2] 7f }

  condition:
    any of them
}