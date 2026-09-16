rule TTP_XOR_MULT_DOSStub_0be6 {
  strings:
    $key_0be6 = { 5f 8e [2] 2b 96 [2] 6c 94 [2] 2b 85 [2] 65 89 [2] 69 83 [2] 7e 88 [2] 65 c6 [2] 58 }

  condition:
    any of them
}