rule TTP_XOR_MULT_DOSStub_399b {
  strings:
    $key_399b = { 6d f3 [2] 19 eb [2] 5e e9 [2] 19 f8 [2] 57 f4 [2] 5b fe [2] 4c f5 [2] 57 bb [2] 6a }

  condition:
    any of them
}