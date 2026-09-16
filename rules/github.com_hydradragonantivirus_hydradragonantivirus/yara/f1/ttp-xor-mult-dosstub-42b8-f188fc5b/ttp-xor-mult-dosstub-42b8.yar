rule TTP_XOR_MULT_DOSStub_42b8 {
  strings:
    $key_42b8 = { 16 d0 [2] 62 c8 [2] 25 ca [2] 62 db [2] 2c d7 [2] 20 dd [2] 37 d6 [2] 2c 98 [2] 11 }

  condition:
    any of them
}