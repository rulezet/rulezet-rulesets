rule TTP_XOR_MULT_DOSStub_f494 {
  strings:
    $key_f494 = { a0 fc [2] d4 e4 [2] 93 e6 [2] d4 f7 [2] 9a fb [2] 96 f1 [2] 81 fa [2] 9a b4 [2] a7 }

  condition:
    any of them
}