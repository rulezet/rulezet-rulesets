rule TTP_XOR_MULT_DOSStub_5cb5 {
  strings:
    $key_5cb5 = { 08 dd [2] 7c c5 [2] 3b c7 [2] 7c d6 [2] 32 da [2] 3e d0 [2] 29 db [2] 32 95 [2] 0f }

  condition:
    any of them
}