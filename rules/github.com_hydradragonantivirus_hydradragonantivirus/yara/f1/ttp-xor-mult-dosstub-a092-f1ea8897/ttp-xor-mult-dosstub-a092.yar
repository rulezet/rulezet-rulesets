rule TTP_XOR_MULT_DOSStub_a092 {
  strings:
    $key_a092 = { f4 fa [2] 80 e2 [2] c7 e0 [2] 80 f1 [2] ce fd [2] c2 f7 [2] d5 fc [2] ce b2 [2] f3 }

  condition:
    any of them
}