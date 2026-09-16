rule TTP_XOR_MULT_DOSStub_4f9b {
  strings:
    $key_4f9b = { 1b f3 [2] 6f eb [2] 28 e9 [2] 6f f8 [2] 21 f4 [2] 2d fe [2] 3a f5 [2] 21 bb [2] 1c }

  condition:
    any of them
}