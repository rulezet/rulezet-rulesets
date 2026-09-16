rule TTP_XOR_MULT_DOSStub_efb3 {
  strings:
    $key_efb3 = { bb db [2] cf c3 [2] 88 c1 [2] cf d0 [2] 81 dc [2] 8d d6 [2] 9a dd [2] 81 93 [2] bc }

  condition:
    any of them
}