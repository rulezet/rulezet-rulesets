rule TTP_XOR_MULT_DOSStub_bea8 {
  strings:
    $key_bea8 = { ea c0 [2] 9e d8 [2] d9 da [2] 9e cb [2] d0 c7 [2] dc cd [2] cb c6 [2] d0 88 [2] ed }

  condition:
    any of them
}