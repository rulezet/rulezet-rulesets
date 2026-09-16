rule TTP_XOR_MULT_DOSStub_beb3 {
  strings:
    $key_beb3 = { ea db [2] 9e c3 [2] d9 c1 [2] 9e d0 [2] d0 dc [2] dc d6 [2] cb dd [2] d0 93 [2] ed }

  condition:
    any of them
}