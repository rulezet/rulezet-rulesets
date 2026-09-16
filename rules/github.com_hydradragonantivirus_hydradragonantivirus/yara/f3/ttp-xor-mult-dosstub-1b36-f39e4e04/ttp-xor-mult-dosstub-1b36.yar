rule TTP_XOR_MULT_DOSStub_1b36 {
  strings:
    $key_1b36 = { 4f 5e [2] 3b 46 [2] 7c 44 [2] 3b 55 [2] 75 59 [2] 79 53 [2] 6e 58 [2] 75 16 [2] 48 }

  condition:
    any of them
}