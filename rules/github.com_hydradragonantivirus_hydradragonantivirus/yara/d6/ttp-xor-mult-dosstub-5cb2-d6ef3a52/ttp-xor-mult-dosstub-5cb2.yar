rule TTP_XOR_MULT_DOSStub_5cb2 {
  strings:
    $key_5cb2 = { 08 da [2] 7c c2 [2] 3b c0 [2] 7c d1 [2] 32 dd [2] 3e d7 [2] 29 dc [2] 32 92 [2] 0f }

  condition:
    any of them
}