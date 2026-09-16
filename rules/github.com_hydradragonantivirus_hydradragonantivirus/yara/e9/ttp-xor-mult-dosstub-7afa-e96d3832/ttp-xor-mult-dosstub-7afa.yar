rule TTP_XOR_MULT_DOSStub_7afa {
  strings:
    $key_7afa = { 2e 92 [2] 5a 8a [2] 1d 88 [2] 5a 99 [2] 14 95 [2] 18 9f [2] 0f 94 [2] 14 da [2] 29 }

  condition:
    any of them
}