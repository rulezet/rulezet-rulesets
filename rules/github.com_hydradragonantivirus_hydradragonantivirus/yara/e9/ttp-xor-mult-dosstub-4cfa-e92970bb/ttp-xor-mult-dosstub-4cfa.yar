rule TTP_XOR_MULT_DOSStub_4cfa {
  strings:
    $key_4cfa = { 18 92 [2] 6c 8a [2] 2b 88 [2] 6c 99 [2] 22 95 [2] 2e 9f [2] 39 94 [2] 22 da [2] 1f }

  condition:
    any of them
}