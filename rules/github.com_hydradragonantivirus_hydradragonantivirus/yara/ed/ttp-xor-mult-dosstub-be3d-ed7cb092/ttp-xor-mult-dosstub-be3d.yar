rule TTP_XOR_MULT_DOSStub_be3d {
  strings:
    $key_be3d = { ea 55 [2] 9e 4d [2] d9 4f [2] 9e 5e [2] d0 52 [2] dc 58 [2] cb 53 [2] d0 1d [2] ed }

  condition:
    any of them
}