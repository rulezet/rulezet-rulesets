rule TTP_XOR_MULT_DOSStub_d593 {
  strings:
    $key_d593 = { 81 fb [2] f5 e3 [2] b2 e1 [2] f5 f0 [2] bb fc [2] b7 f6 [2] a0 fd [2] bb b3 [2] 86 }

  condition:
    any of them
}