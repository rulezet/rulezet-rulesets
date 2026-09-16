rule TTP_XOR_MULT_DOSStub_4ace {
  strings:
    $key_4ace = { 1e a6 [2] 6a be [2] 2d bc [2] 6a ad [2] 24 a1 [2] 28 ab [2] 3f a0 [2] 24 ee [2] 19 }

  condition:
    any of them
}