rule TTP_XOR_MULT_DOSStub_1895 {
  strings:
    $key_1895 = { 4c fd [2] 38 e5 [2] 7f e7 [2] 38 f6 [2] 76 fa [2] 7a f0 [2] 6d fb [2] 76 b5 [2] 4b }

  condition:
    any of them
}