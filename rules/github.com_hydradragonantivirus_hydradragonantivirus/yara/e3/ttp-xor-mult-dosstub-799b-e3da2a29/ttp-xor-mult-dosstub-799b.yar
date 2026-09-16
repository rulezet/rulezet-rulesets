rule TTP_XOR_MULT_DOSStub_799b {
  strings:
    $key_799b = { 2d f3 [2] 59 eb [2] 1e e9 [2] 59 f8 [2] 17 f4 [2] 1b fe [2] 0c f5 [2] 17 bb [2] 2a }

  condition:
    any of them
}