rule TTP_XOR_MULT_DOSStub_be0b {
  strings:
    $key_be0b = { ea 63 [2] 9e 7b [2] d9 79 [2] 9e 68 [2] d0 64 [2] dc 6e [2] cb 65 [2] d0 2b [2] ed }

  condition:
    any of them
}