rule TTP_XOR_MULT_DOSStub_a494 {
  strings:
    $key_a494 = { f0 fc [2] 84 e4 [2] c3 e6 [2] 84 f7 [2] ca fb [2] c6 f1 [2] d1 fa [2] ca b4 [2] f7 }

  condition:
    any of them
}