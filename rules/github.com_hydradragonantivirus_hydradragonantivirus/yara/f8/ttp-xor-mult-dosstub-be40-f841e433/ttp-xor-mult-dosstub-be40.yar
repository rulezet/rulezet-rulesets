rule TTP_XOR_MULT_DOSStub_be40 {
  strings:
    $key_be40 = { ea 28 [2] 9e 30 [2] d9 32 [2] 9e 23 [2] d0 2f [2] dc 25 [2] cb 2e [2] d0 60 [2] ed }

  condition:
    any of them
}