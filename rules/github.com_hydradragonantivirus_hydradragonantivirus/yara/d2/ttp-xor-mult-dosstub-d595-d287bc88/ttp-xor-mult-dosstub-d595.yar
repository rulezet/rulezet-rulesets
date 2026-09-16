rule TTP_XOR_MULT_DOSStub_d595 {
  strings:
    $key_d595 = { 81 fd [2] f5 e5 [2] b2 e7 [2] f5 f6 [2] bb fa [2] b7 f0 [2] a0 fb [2] bb b5 [2] 86 }

  condition:
    any of them
}