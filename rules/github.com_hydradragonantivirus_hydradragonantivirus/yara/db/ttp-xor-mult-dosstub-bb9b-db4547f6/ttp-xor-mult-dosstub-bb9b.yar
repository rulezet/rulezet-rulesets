rule TTP_XOR_MULT_DOSStub_bb9b {
  strings:
    $key_bb9b = { ef f3 [2] 9b eb [2] dc e9 [2] 9b f8 [2] d5 f4 [2] d9 fe [2] ce f5 [2] d5 bb [2] e8 }

  condition:
    any of them
}