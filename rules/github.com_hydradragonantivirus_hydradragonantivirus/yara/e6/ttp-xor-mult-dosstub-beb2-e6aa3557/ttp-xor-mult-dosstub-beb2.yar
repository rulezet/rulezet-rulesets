rule TTP_XOR_MULT_DOSStub_beb2 {
  strings:
    $key_beb2 = { ea da [2] 9e c2 [2] d9 c0 [2] 9e d1 [2] d0 dd [2] dc d7 [2] cb dc [2] d0 92 [2] ed }

  condition:
    any of them
}