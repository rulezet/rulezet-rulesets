rule TTP_XOR_MULT_DOSStub_be88 {
  strings:
    $key_be88 = { ea e0 [2] 9e f8 [2] d9 fa [2] 9e eb [2] d0 e7 [2] dc ed [2] cb e6 [2] d0 a8 [2] ed }

  condition:
    any of them
}