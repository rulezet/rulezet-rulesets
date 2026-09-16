rule TTP_XOR_MULT_DOSStub_1cb9 {
  strings:
    $key_1cb9 = { 48 d1 [2] 3c c9 [2] 7b cb [2] 3c da [2] 72 d6 [2] 7e dc [2] 69 d7 [2] 72 99 [2] 4f }

  condition:
    any of them
}