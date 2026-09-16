rule TTP_XOR_MULT_DOSStub_e89b {
  strings:
    $key_e89b = { bc f3 [2] c8 eb [2] 8f e9 [2] c8 f8 [2] 86 f4 [2] 8a fe [2] 9d f5 [2] 86 bb [2] bb }

  condition:
    any of them
}