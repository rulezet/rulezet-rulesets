rule TTP_XOR_MULT_DOSStub_b8cb {
  strings:
    $key_b8cb = { ec a3 [2] 98 bb [2] df b9 [2] 98 a8 [2] d6 a4 [2] da ae [2] cd a5 [2] d6 eb [2] eb }

  condition:
    any of them
}