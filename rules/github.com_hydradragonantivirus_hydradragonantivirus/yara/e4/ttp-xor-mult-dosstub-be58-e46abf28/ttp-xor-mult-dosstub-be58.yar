rule TTP_XOR_MULT_DOSStub_be58 {
  strings:
    $key_be58 = { ea 30 [2] 9e 28 [2] d9 2a [2] 9e 3b [2] d0 37 [2] dc 3d [2] cb 36 [2] d0 78 [2] ed }

  condition:
    any of them
}