rule TTP_XOR_MULT_DOSStub_3cb2 {
  strings:
    $key_3cb2 = { 68 da [2] 1c c2 [2] 5b c0 [2] 1c d1 [2] 52 dd [2] 5e d7 [2] 49 dc [2] 52 92 [2] 6f }

  condition:
    any of them
}