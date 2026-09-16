rule TTP_XOR_MULT_DOSStub_0a9b {
  strings:
    $key_0a9b = { 5e f3 [2] 2a eb [2] 6d e9 [2] 2a f8 [2] 64 f4 [2] 68 fe [2] 7f f5 [2] 64 bb [2] 59 }

  condition:
    any of them
}