rule TTP_XOR_MULT_DOSStub_be24 {
  strings:
    $key_be24 = { ea 4c [2] 9e 54 [2] d9 56 [2] 9e 47 [2] d0 4b [2] dc 41 [2] cb 4a [2] d0 04 [2] ed }

  condition:
    any of them
}