rule TTP_XOR_MULT_DOSStub_66b5 {
  strings:
    $key_66b5 = { 32 dd [2] 46 c5 [2] 01 c7 [2] 46 d6 [2] 08 da [2] 04 d0 [2] 13 db [2] 08 95 [2] 35 }

  condition:
    any of them
}