rule TTP_XOR_MULT_DOSStub_4a9a {
  strings:
    $key_4a9a = { 1e f2 [2] 6a ea [2] 2d e8 [2] 6a f9 [2] 24 f5 [2] 28 ff [2] 3f f4 [2] 24 ba [2] 19 }

  condition:
    any of them
}