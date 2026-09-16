rule TTP_XOR_MULT_DOSStub_3cb5 {
  strings:
    $key_3cb5 = { 68 dd [2] 1c c5 [2] 5b c7 [2] 1c d6 [2] 52 da [2] 5e d0 [2] 49 db [2] 52 95 [2] 6f }

  condition:
    any of them
}