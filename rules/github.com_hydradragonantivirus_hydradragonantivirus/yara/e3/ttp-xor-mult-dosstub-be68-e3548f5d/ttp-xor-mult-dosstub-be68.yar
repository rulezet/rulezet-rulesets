rule TTP_XOR_MULT_DOSStub_be68 {
  strings:
    $key_be68 = { ea 00 [2] 9e 18 [2] d9 1a [2] 9e 0b [2] d0 07 [2] dc 0d [2] cb 06 [2] d0 48 [2] ed }

  condition:
    any of them
}