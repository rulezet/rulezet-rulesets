rule TTP_XOR_MULT_DOSStub_689b {
  strings:
    $key_689b = { 3c f3 [2] 48 eb [2] 0f e9 [2] 48 f8 [2] 06 f4 [2] 0a fe [2] 1d f5 [2] 06 bb [2] 3b }

  condition:
    any of them
}