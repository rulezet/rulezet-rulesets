rule TTP_XOR_MULT_DOSStub_49a8 {
  strings:
    $key_49a8 = { 1d c0 [2] 69 d8 [2] 2e da [2] 69 cb [2] 27 c7 [2] 2b cd [2] 3c c6 [2] 27 88 [2] 1a }

  condition:
    any of them
}