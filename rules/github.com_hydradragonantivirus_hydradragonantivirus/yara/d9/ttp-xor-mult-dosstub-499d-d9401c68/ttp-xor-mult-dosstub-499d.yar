rule TTP_XOR_MULT_DOSStub_499d {
  strings:
    $key_499d = { 1d f5 [2] 69 ed [2] 2e ef [2] 69 fe [2] 27 f2 [2] 2b f8 [2] 3c f3 [2] 27 bd [2] 1a }

  condition:
    any of them
}