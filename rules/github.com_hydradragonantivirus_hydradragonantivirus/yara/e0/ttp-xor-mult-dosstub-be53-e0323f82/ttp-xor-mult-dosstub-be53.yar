rule TTP_XOR_MULT_DOSStub_be53 {
  strings:
    $key_be53 = { ea 3b [2] 9e 23 [2] d9 21 [2] 9e 30 [2] d0 3c [2] dc 36 [2] cb 3d [2] d0 73 [2] ed }

  condition:
    any of them
}