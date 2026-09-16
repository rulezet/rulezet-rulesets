rule TTP_XOR_MULT_DOSStub_099b {
  strings:
    $key_099b = { 5d f3 [2] 29 eb [2] 6e e9 [2] 29 f8 [2] 67 f4 [2] 6b fe [2] 7c f5 [2] 67 bb [2] 5a }

  condition:
    any of them
}