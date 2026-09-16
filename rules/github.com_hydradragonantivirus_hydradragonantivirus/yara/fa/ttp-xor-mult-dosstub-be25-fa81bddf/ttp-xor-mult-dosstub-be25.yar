rule TTP_XOR_MULT_DOSStub_be25 {
  strings:
    $key_be25 = { ea 4d [2] 9e 55 [2] d9 57 [2] 9e 46 [2] d0 4a [2] dc 40 [2] cb 4b [2] d0 05 [2] ed }

  condition:
    any of them
}