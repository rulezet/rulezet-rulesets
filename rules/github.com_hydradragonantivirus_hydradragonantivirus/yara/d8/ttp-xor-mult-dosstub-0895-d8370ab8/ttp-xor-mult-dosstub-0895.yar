rule TTP_XOR_MULT_DOSStub_0895 {
  strings:
    $key_0895 = { 5c fd [2] 28 e5 [2] 6f e7 [2] 28 f6 [2] 66 fa [2] 6a f0 [2] 7d fb [2] 66 b5 [2] 5b }

  condition:
    any of them
}