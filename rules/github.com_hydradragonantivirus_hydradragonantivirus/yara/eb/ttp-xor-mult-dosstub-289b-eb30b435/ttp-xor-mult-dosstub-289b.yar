rule TTP_XOR_MULT_DOSStub_289b {
  strings:
    $key_289b = { 7c f3 [2] 08 eb [2] 4f e9 [2] 08 f8 [2] 46 f4 [2] 4a fe [2] 5d f5 [2] 46 bb [2] 7b }

  condition:
    any of them
}