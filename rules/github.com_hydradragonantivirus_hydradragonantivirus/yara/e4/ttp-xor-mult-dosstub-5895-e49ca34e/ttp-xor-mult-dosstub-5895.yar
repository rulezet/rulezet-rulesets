rule TTP_XOR_MULT_DOSStub_5895 {
  strings:
    $key_5895 = { 0c fd [2] 78 e5 [2] 3f e7 [2] 78 f6 [2] 36 fa [2] 3a f0 [2] 2d fb [2] 36 b5 [2] 0b }

  condition:
    any of them
}