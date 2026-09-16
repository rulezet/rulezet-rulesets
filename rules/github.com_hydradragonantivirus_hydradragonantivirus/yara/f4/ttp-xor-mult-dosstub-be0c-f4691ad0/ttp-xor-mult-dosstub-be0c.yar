rule TTP_XOR_MULT_DOSStub_be0c {
  strings:
    $key_be0c = { ea 64 [2] 9e 7c [2] d9 7e [2] 9e 6f [2] d0 63 [2] dc 69 [2] cb 62 [2] d0 2c [2] ed }

  condition:
    any of them
}