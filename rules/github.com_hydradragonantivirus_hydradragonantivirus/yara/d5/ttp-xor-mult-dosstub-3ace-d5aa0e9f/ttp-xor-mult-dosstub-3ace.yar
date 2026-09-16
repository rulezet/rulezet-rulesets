rule TTP_XOR_MULT_DOSStub_3ace {
  strings:
    $key_3ace = { 6e a6 [2] 1a be [2] 5d bc [2] 1a ad [2] 54 a1 [2] 58 ab [2] 4f a0 [2] 54 ee [2] 69 }

  condition:
    any of them
}