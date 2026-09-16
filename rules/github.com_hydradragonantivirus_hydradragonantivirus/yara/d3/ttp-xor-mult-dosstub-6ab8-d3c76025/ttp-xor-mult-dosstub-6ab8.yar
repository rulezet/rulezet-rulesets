rule TTP_XOR_MULT_DOSStub_6ab8 {
  strings:
    $key_6ab8 = { 3e d0 [2] 4a c8 [2] 0d ca [2] 4a db [2] 04 d7 [2] 08 dd [2] 1f d6 [2] 04 98 [2] 39 }

  condition:
    any of them
}