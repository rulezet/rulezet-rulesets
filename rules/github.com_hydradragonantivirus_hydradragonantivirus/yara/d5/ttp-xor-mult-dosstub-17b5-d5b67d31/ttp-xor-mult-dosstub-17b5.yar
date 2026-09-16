rule TTP_XOR_MULT_DOSStub_17b5 {
  strings:
    $key_17b5 = { 43 dd [2] 37 c5 [2] 70 c7 [2] 37 d6 [2] 79 da [2] 75 d0 [2] 62 db [2] 79 95 [2] 44 }

  condition:
    any of them
}