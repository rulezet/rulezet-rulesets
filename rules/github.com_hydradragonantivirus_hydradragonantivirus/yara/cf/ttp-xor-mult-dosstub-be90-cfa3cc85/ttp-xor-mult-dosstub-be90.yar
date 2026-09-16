rule TTP_XOR_MULT_DOSStub_be90 {
  strings:
    $key_be90 = { ea f8 [2] 9e e0 [2] d9 e2 [2] 9e f3 [2] d0 ff [2] dc f5 [2] cb fe [2] d0 b0 [2] ed }

  condition:
    any of them
}