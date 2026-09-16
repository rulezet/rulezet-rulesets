rule TTP_XOR_MULT_DOSStub_be72 {
  strings:
    $key_be72 = { ea 1a [2] 9e 02 [2] d9 00 [2] 9e 11 [2] d0 1d [2] dc 17 [2] cb 1c [2] d0 52 [2] ed }

  condition:
    any of them
}