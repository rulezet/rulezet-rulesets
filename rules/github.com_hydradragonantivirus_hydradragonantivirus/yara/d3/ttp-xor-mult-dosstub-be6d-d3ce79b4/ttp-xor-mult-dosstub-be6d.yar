rule TTP_XOR_MULT_DOSStub_be6d {
  strings:
    $key_be6d = { ea 05 [2] 9e 1d [2] d9 1f [2] 9e 0e [2] d0 02 [2] dc 08 [2] cb 03 [2] d0 4d [2] ed }

  condition:
    any of them
}