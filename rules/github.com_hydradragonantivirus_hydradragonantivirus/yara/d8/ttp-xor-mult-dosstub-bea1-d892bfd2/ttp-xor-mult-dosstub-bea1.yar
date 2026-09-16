rule TTP_XOR_MULT_DOSStub_bea1 {
  strings:
    $key_bea1 = { ea c9 [2] 9e d1 [2] d9 d3 [2] 9e c2 [2] d0 ce [2] dc c4 [2] cb cf [2] d0 81 [2] ed }

  condition:
    any of them
}