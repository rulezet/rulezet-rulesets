rule TTP_XOR_MULT_DOSStub_d599 {
  strings:
    $key_d599 = { 81 f1 [2] f5 e9 [2] b2 eb [2] f5 fa [2] bb f6 [2] b7 fc [2] a0 f7 [2] bb b9 [2] 86 }

  condition:
    any of them
}