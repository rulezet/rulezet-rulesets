rule TTP_XOR_MULT_DOSStub_65b5 {
  strings:
    $key_65b5 = { 31 dd [2] 45 c5 [2] 02 c7 [2] 45 d6 [2] 0b da [2] 07 d0 [2] 10 db [2] 0b 95 [2] 36 }

  condition:
    any of them
}