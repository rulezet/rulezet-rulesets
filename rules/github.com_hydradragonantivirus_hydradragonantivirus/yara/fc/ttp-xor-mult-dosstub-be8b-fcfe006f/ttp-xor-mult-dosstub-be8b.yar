rule TTP_XOR_MULT_DOSStub_be8b {
  strings:
    $key_be8b = { ea e3 [2] 9e fb [2] d9 f9 [2] 9e e8 [2] d0 e4 [2] dc ee [2] cb e5 [2] d0 ab [2] ed }

  condition:
    any of them
}