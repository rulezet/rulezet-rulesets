rule TTP_XOR_MULT_DOSStub_1b47 {
  strings:
    $key_1b47 = { 4f 2f [2] 3b 37 [2] 7c 35 [2] 3b 24 [2] 75 28 [2] 79 22 [2] 6e 29 [2] 75 67 [2] 48 }

  condition:
    any of them
}