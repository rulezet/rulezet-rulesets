rule TTP_XOR_MULT_DOSStub_6cb8 {
  strings:
    $key_6cb8 = { 38 d0 [2] 4c c8 [2] 0b ca [2] 4c db [2] 02 d7 [2] 0e dd [2] 19 d6 [2] 02 98 [2] 3f }

  condition:
    any of them
}