rule TTP_XOR_MULT_DOSStub_be7f {
  strings:
    $key_be7f = { ea 17 [2] 9e 0f [2] d9 0d [2] 9e 1c [2] d0 10 [2] dc 1a [2] cb 11 [2] d0 5f [2] ed }

  condition:
    any of them
}