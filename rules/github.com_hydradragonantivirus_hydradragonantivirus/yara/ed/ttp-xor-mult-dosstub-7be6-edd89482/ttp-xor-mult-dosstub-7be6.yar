rule TTP_XOR_MULT_DOSStub_7be6 {
  strings:
    $key_7be6 = { 2f 8e [2] 5b 96 [2] 1c 94 [2] 5b 85 [2] 15 89 [2] 19 83 [2] 0e 88 [2] 15 c6 [2] 28 }

  condition:
    any of them
}