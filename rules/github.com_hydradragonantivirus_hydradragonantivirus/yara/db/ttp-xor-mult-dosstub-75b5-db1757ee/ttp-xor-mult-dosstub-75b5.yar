rule TTP_XOR_MULT_DOSStub_75b5 {
  strings:
    $key_75b5 = { 21 dd [2] 55 c5 [2] 12 c7 [2] 55 d6 [2] 1b da [2] 17 d0 [2] 00 db [2] 1b 95 [2] 26 }

  condition:
    any of them
}