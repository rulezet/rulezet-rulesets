rule TTP_XOR_MULT_DOSStub_4f9a {
  strings:
    $key_4f9a = { 1b f2 [2] 6f ea [2] 28 e8 [2] 6f f9 [2] 21 f5 [2] 2d ff [2] 3a f4 [2] 21 ba [2] 1c }

  condition:
    any of them
}