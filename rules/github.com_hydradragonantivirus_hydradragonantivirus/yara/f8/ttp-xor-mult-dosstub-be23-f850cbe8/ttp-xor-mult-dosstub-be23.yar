rule TTP_XOR_MULT_DOSStub_be23 {
  strings:
    $key_be23 = { ea 4b [2] 9e 53 [2] d9 51 [2] 9e 40 [2] d0 4c [2] dc 46 [2] cb 4d [2] d0 03 [2] ed }

  condition:
    any of them
}