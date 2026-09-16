rule TTP_XOR_MULT_DOSStub_77e6 {
  strings:
    $key_77e6 = { 23 8e [2] 57 96 [2] 10 94 [2] 57 85 [2] 19 89 [2] 15 83 [2] 02 88 [2] 19 c6 [2] 24 }

  condition:
    any of them
}