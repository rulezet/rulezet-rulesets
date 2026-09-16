rule TTP_XOR_MULT_DOSStub_5cb8 {
  strings:
    $key_5cb8 = { 08 d0 [2] 7c c8 [2] 3b ca [2] 7c db [2] 32 d7 [2] 3e dd [2] 29 d6 [2] 32 98 [2] 0f }

  condition:
    any of them
}