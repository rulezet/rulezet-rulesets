rule TTP_XOR_MULT_DOSStub_60b5 {
  strings:
    $key_60b5 = { 34 dd [2] 40 c5 [2] 07 c7 [2] 40 d6 [2] 0e da [2] 02 d0 [2] 15 db [2] 0e 95 [2] 33 }

  condition:
    any of them
}