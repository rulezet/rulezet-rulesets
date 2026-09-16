rule TTP_XOR_MULT_DOSStub_66b3 {
  strings:
    $key_66b3 = { 32 db [2] 46 c3 [2] 01 c1 [2] 46 d0 [2] 08 dc [2] 04 d6 [2] 13 dd [2] 08 93 [2] 35 }

  condition:
    any of them
}