rule TTP_XOR_MULT_DOSStub_42b3 {
  strings:
    $key_42b3 = { 16 db [2] 62 c3 [2] 25 c1 [2] 62 d0 [2] 2c dc [2] 20 d6 [2] 37 dd [2] 2c 93 [2] 11 }

  condition:
    any of them
}