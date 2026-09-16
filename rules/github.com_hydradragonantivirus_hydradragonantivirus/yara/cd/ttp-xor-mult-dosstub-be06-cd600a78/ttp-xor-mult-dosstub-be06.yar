rule TTP_XOR_MULT_DOSStub_be06 {
  strings:
    $key_be06 = { ea 6e [2] 9e 76 [2] d9 74 [2] 9e 65 [2] d0 69 [2] dc 63 [2] cb 68 [2] d0 26 [2] ed }

  condition:
    any of them
}