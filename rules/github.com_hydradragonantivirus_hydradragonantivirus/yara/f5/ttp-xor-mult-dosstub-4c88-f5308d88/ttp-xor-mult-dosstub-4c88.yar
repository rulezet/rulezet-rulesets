rule TTP_XOR_MULT_DOSStub_4c88 {
  strings:
    $key_4c88 = { 18 e0 [2] 6c f8 [2] 2b fa [2] 6c eb [2] 22 e7 [2] 2e ed [2] 39 e6 [2] 22 a8 [2] 1f }

  condition:
    any of them
}