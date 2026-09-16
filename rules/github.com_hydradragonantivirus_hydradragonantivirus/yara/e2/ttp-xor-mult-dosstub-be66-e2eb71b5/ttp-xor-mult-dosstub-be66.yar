rule TTP_XOR_MULT_DOSStub_be66 {
  strings:
    $key_be66 = { ea 0e [2] 9e 16 [2] d9 14 [2] 9e 05 [2] d0 09 [2] dc 03 [2] cb 08 [2] d0 46 [2] ed }

  condition:
    any of them
}