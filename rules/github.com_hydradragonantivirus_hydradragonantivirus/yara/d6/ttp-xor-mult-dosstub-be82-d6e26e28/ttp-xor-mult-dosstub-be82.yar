rule TTP_XOR_MULT_DOSStub_be82 {
  strings:
    $key_be82 = { ea ea [2] 9e f2 [2] d9 f0 [2] 9e e1 [2] d0 ed [2] dc e7 [2] cb ec [2] d0 a2 [2] ed }

  condition:
    any of them
}