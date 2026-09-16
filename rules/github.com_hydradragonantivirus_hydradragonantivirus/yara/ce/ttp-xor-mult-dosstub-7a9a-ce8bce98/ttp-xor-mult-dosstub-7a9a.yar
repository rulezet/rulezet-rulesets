rule TTP_XOR_MULT_DOSStub_7a9a {
  strings:
    $key_7a9a = { 2e f2 [2] 5a ea [2] 1d e8 [2] 5a f9 [2] 14 f5 [2] 18 ff [2] 0f f4 [2] 14 ba [2] 29 }

  condition:
    any of them
}