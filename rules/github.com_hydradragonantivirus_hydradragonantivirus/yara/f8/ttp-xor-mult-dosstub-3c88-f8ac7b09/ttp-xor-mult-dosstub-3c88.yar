rule TTP_XOR_MULT_DOSStub_3c88 {
  strings:
    $key_3c88 = { 68 e0 [2] 1c f8 [2] 5b fa [2] 1c eb [2] 52 e7 [2] 5e ed [2] 49 e6 [2] 52 a8 [2] 6f }

  condition:
    any of them
}