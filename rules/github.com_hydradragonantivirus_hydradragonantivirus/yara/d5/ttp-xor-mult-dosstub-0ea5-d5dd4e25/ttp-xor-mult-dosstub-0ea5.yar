rule TTP_XOR_MULT_DOSStub_0ea5 {
  strings:
    $key_0ea5 = { 5a cd [2] 2e d5 [2] 69 d7 [2] 2e c6 [2] 60 ca [2] 6c c0 [2] 7b cb [2] 60 85 [2] 5d }

  condition:
    any of them
}