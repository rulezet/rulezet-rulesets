rule TTP_XOR_MULT_DOSStub_3be6 {
  strings:
    $key_3be6 = { 6f 8e [2] 1b 96 [2] 5c 94 [2] 1b 85 [2] 55 89 [2] 59 83 [2] 4e 88 [2] 55 c6 [2] 68 }

  condition:
    any of them
}