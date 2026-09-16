rule TTP_XOR_MULT_DOSStub_62e6 {
  strings:
    $key_62e6 = { 36 8e [2] 42 96 [2] 05 94 [2] 42 85 [2] 0c 89 [2] 00 83 [2] 17 88 [2] 0c c6 [2] 31 }

  condition:
    any of them
}