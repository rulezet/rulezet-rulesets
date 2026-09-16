rule TTP_XOR_MULT_DOSStub_d592 {
  strings:
    $key_d592 = { 81 fa [2] f5 e2 [2] b2 e0 [2] f5 f1 [2] bb fd [2] b7 f7 [2] a0 fc [2] bb b2 [2] 86 }

  condition:
    any of them
}