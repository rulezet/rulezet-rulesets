rule TTP_XOR_MULT_DOSStub_74b5 {
  strings:
    $key_74b5 = { 20 dd [2] 54 c5 [2] 13 c7 [2] 54 d6 [2] 1a da [2] 16 d0 [2] 01 db [2] 1a 95 [2] 27 }

  condition:
    any of them
}