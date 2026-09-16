rule TTP_XOR_MULT_DOSStub_799a {
  strings:
    $key_799a = { 2d f2 [2] 59 ea [2] 1e e8 [2] 59 f9 [2] 17 f5 [2] 1b ff [2] 0c f4 [2] 17 ba [2] 2a }

  condition:
    any of them
}