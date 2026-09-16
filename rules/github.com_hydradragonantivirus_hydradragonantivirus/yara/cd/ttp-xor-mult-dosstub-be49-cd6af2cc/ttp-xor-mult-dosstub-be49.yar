rule TTP_XOR_MULT_DOSStub_be49 {
  strings:
    $key_be49 = { ea 21 [2] 9e 39 [2] d9 3b [2] 9e 2a [2] d0 26 [2] dc 2c [2] cb 27 [2] d0 69 [2] ed }

  condition:
    any of them
}