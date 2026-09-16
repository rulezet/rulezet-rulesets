rule TTP_XOR_MULT_DOSStub_4ab8 {
  strings:
    $key_4ab8 = { 1e d0 [2] 6a c8 [2] 2d ca [2] 6a db [2] 24 d7 [2] 28 dd [2] 3f d6 [2] 24 98 [2] 19 }

  condition:
    any of them
}