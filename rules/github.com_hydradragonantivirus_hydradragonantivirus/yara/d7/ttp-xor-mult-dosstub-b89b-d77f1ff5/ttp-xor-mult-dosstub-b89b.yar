rule TTP_XOR_MULT_DOSStub_b89b {
  strings:
    $key_b89b = { ec f3 [2] 98 eb [2] df e9 [2] 98 f8 [2] d6 f4 [2] da fe [2] cd f5 [2] d6 bb [2] eb }

  condition:
    any of them
}