rule TTP_XOR_MULT_DOSStub_9f92 {
  strings:
    $key_9f92 = { cb fa [2] bf e2 [2] f8 e0 [2] bf f1 [2] f1 fd [2] fd f7 [2] ea fc [2] f1 b2 [2] cc }

  condition:
    any of them
}