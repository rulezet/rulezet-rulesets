rule TTP_XOR_MULT_DOSStub_be91 {
  strings:
    $key_be91 = { ea f9 [2] 9e e1 [2] d9 e3 [2] 9e f2 [2] d0 fe [2] dc f4 [2] cb ff [2] d0 b1 [2] ed }

  condition:
    any of them
}