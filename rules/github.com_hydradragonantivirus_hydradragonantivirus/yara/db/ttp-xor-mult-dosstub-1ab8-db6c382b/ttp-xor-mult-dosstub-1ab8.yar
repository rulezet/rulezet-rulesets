rule TTP_XOR_MULT_DOSStub_1ab8 {
  strings:
    $key_1ab8 = { 4e d0 [2] 3a c8 [2] 7d ca [2] 3a db [2] 74 d7 [2] 78 dd [2] 6f d6 [2] 74 98 [2] 49 }

  condition:
    any of them
}