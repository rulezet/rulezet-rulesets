rule TTP_XOR_MULT_DOSStub_bee2 {
  strings:
    $key_bee2 = { ea 8a [2] 9e 92 [2] d9 90 [2] 9e 81 [2] d0 8d [2] dc 87 [2] cb 8c [2] d0 c2 [2] ed }

  condition:
    any of them
}