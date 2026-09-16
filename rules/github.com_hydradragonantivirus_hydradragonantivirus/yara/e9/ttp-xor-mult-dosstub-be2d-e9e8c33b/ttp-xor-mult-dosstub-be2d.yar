rule TTP_XOR_MULT_DOSStub_be2d {
  strings:
    $key_be2d = { ea 45 [2] 9e 5d [2] d9 5f [2] 9e 4e [2] d0 42 [2] dc 48 [2] cb 43 [2] d0 0d [2] ed }

  condition:
    any of them
}