rule TTP_XOR_MULT_DOSStub_be45 {
  strings:
    $key_be45 = { ea 2d [2] 9e 35 [2] d9 37 [2] 9e 26 [2] d0 2a [2] dc 20 [2] cb 2b [2] d0 65 [2] ed }

  condition:
    any of them
}