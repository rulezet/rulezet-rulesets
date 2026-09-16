rule TTP_XOR_MULT_DOSStub_5ea5 {
  strings:
    $key_5ea5 = { 0a cd [2] 7e d5 [2] 39 d7 [2] 7e c6 [2] 30 ca [2] 3c c0 [2] 2b cb [2] 30 85 [2] 0d }

  condition:
    any of them
}