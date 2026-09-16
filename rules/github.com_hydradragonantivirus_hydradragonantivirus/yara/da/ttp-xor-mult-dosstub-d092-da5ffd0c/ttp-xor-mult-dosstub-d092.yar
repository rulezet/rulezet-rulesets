rule TTP_XOR_MULT_DOSStub_d092 {
  strings:
    $key_d092 = { 84 fa [2] f0 e2 [2] b7 e0 [2] f0 f1 [2] be fd [2] b2 f7 [2] a5 fc [2] be b2 [2] 83 }

  condition:
    any of them
}