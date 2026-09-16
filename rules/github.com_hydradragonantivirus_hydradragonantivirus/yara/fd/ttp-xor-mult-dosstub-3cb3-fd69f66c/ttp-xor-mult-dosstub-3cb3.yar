rule TTP_XOR_MULT_DOSStub_3cb3 {
  strings:
    $key_3cb3 = { 68 db [2] 1c c3 [2] 5b c1 [2] 1c d0 [2] 52 dc [2] 5e d6 [2] 49 dd [2] 52 93 [2] 6f }

  condition:
    any of them
}