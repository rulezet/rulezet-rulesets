rule TTP_XOR_MULT_DOSStub_d992 {
  strings:
    $key_d992 = { 8d fa [2] f9 e2 [2] be e0 [2] f9 f1 [2] b7 fd [2] bb f7 [2] ac fc [2] b7 b2 [2] 8a }

  condition:
    any of them
}