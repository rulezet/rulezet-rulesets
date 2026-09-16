rule TTP_XOR_MULT_DOSStub_be83 {
  strings:
    $key_be83 = { ea eb [2] 9e f3 [2] d9 f1 [2] 9e e0 [2] d0 ec [2] dc e6 [2] cb ed [2] d0 a3 [2] ed }

  condition:
    any of them
}