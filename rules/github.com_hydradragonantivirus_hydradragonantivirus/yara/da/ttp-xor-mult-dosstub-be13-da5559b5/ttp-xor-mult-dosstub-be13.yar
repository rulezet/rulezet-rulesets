rule TTP_XOR_MULT_DOSStub_be13 {
  strings:
    $key_be13 = { ea 7b [2] 9e 63 [2] d9 61 [2] 9e 70 [2] d0 7c [2] dc 76 [2] cb 7d [2] d0 33 [2] ed }

  condition:
    any of them
}