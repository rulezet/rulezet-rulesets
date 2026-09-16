rule TTP_XOR_MULT_DOSStub_7895 {
  strings:
    $key_7895 = { 2c fd [2] 58 e5 [2] 1f e7 [2] 58 f6 [2] 16 fa [2] 1a f0 [2] 0d fb [2] 16 b5 [2] 2b }

  condition:
    any of them
}