rule TTP_XOR_MULT_DOSStub_be3e {
  strings:
    $key_be3e = { ea 56 [2] 9e 4e [2] d9 4c [2] 9e 5d [2] d0 51 [2] dc 5b [2] cb 50 [2] d0 1e [2] ed }

  condition:
    any of them
}