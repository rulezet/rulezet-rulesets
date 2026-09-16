rule TTP_XOR_MULT_DOSStub_be26 {
  strings:
    $key_be26 = { ea 4e [2] 9e 56 [2] d9 54 [2] 9e 45 [2] d0 49 [2] dc 43 [2] cb 48 [2] d0 06 [2] ed }

  condition:
    any of them
}