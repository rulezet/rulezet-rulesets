rule TTP_XOR_MULT_DOSStub_be1f {
  strings:
    $key_be1f = { ea 77 [2] 9e 6f [2] d9 6d [2] 9e 7c [2] d0 70 [2] dc 7a [2] cb 71 [2] d0 3f [2] ed }

  condition:
    any of them
}