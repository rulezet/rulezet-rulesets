rule TTP_XOR_MULT_DOSStub_befa {
  strings:
    $key_befa = { ea 92 [2] 9e 8a [2] d9 88 [2] 9e 99 [2] d0 95 [2] dc 9f [2] cb 94 [2] d0 da [2] ed }

  condition:
    any of them
}