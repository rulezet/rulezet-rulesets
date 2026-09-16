rule TTP_XOR_MULT_DOSStub_a094 {
  strings:
    $key_a094 = { f4 fc [2] 80 e4 [2] c7 e6 [2] 80 f7 [2] ce fb [2] c2 f1 [2] d5 fa [2] ce b4 [2] f3 }

  condition:
    any of them
}