rule TTP_XOR_MULT_DOSStub_1cb5 {
  strings:
    $key_1cb5 = { 48 dd [2] 3c c5 [2] 7b c7 [2] 3c d6 [2] 72 da [2] 7e d0 [2] 69 db [2] 72 95 [2] 4f }

  condition:
    any of them
}