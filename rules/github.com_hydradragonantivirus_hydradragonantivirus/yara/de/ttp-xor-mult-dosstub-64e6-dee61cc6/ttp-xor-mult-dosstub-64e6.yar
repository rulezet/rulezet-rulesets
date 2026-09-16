rule TTP_XOR_MULT_DOSStub_64e6 {
  strings:
    $key_64e6 = { 30 8e [2] 44 96 [2] 03 94 [2] 44 85 [2] 0a 89 [2] 06 83 [2] 11 88 [2] 0a c6 [2] 37 }

  condition:
    any of them
}