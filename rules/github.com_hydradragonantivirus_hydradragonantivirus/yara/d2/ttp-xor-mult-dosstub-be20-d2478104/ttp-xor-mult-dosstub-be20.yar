rule TTP_XOR_MULT_DOSStub_be20 {
  strings:
    $key_be20 = { ea 48 [2] 9e 50 [2] d9 52 [2] 9e 43 [2] d0 4f [2] dc 45 [2] cb 4e [2] d0 00 [2] ed }

  condition:
    any of them
}