rule TTP_XOR_MULT_DOSStub_2f9b {
  strings:
    $key_2f9b = { 7b f3 [2] 0f eb [2] 48 e9 [2] 0f f8 [2] 41 f4 [2] 4d fe [2] 5a f5 [2] 41 bb [2] 7c }

  condition:
    any of them
}