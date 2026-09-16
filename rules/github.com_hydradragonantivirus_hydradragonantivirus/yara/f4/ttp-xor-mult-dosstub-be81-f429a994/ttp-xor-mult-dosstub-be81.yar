rule TTP_XOR_MULT_DOSStub_be81 {
  strings:
    $key_be81 = { ea e9 [2] 9e f1 [2] d9 f3 [2] 9e e2 [2] d0 ee [2] dc e4 [2] cb ef [2] d0 a1 [2] ed }

  condition:
    any of them
}