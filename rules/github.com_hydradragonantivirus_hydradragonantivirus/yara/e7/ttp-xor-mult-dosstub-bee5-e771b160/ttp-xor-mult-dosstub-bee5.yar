rule TTP_XOR_MULT_DOSStub_bee5 {
  strings:
    $key_bee5 = { ea 8d [2] 9e 95 [2] d9 97 [2] 9e 86 [2] d0 8a [2] dc 80 [2] cb 8b [2] d0 c5 [2] ed }

  condition:
    any of them
}