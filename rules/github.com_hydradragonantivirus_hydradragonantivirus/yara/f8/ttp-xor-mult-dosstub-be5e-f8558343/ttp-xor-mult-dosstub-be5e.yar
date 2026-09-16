rule TTP_XOR_MULT_DOSStub_be5e {
  strings:
    $key_be5e = { ea 36 [2] 9e 2e [2] d9 2c [2] 9e 3d [2] d0 31 [2] dc 3b [2] cb 30 [2] d0 7e [2] ed }

  condition:
    any of them
}