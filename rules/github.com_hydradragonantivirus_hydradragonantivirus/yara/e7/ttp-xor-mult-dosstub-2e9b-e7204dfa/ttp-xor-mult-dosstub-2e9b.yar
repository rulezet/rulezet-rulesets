rule TTP_XOR_MULT_DOSStub_2e9b {
  strings:
    $key_2e9b = { 7a f3 [2] 0e eb [2] 49 e9 [2] 0e f8 [2] 40 f4 [2] 4c fe [2] 5b f5 [2] 40 bb [2] 7d }

  condition:
    any of them
}