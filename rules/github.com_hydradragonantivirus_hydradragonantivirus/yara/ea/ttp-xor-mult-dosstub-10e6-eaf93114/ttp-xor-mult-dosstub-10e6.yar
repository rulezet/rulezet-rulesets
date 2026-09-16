rule TTP_XOR_MULT_DOSStub_10e6 {
  strings:
    $key_10e6 = { 44 8e [2] 30 96 [2] 77 94 [2] 30 85 [2] 7e 89 [2] 72 83 [2] 65 88 [2] 7e c6 [2] 43 }

  condition:
    any of them
}