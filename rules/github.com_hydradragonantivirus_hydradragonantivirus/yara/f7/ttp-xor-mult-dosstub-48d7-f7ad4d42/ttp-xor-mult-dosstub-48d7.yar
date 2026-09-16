rule TTP_XOR_MULT_DOSStub_48d7 {
  strings:
    $key_48d7 = { 1c bf [2] 68 a7 [2] 2f a5 [2] 68 b4 [2] 26 b8 [2] 2a b2 [2] 3d b9 [2] 26 f7 [2] 1b }

  condition:
    any of them
}