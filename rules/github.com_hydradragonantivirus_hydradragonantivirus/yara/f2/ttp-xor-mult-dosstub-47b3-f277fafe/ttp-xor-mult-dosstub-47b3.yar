rule TTP_XOR_MULT_DOSStub_47b3 {
  strings:
    $key_47b3 = { 13 db [2] 67 c3 [2] 20 c1 [2] 67 d0 [2] 29 dc [2] 25 d6 [2] 32 dd [2] 29 93 [2] 14 }

  condition:
    any of them
}