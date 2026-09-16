rule TTP_XOR_MULT_DOSStub_5ea8 {
  strings:
    $key_5ea8 = { 0a c0 [2] 7e d8 [2] 39 da [2] 7e cb [2] 30 c7 [2] 3c cd [2] 2b c6 [2] 30 88 [2] 0d }

  condition:
    any of them
}