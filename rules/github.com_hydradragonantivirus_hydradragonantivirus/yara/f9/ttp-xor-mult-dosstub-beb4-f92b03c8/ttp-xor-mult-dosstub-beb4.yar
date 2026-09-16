rule TTP_XOR_MULT_DOSStub_beb4 {
  strings:
    $key_beb4 = { ea dc [2] 9e c4 [2] d9 c6 [2] 9e d7 [2] d0 db [2] dc d1 [2] cb da [2] d0 94 [2] ed }

  condition:
    any of them
}