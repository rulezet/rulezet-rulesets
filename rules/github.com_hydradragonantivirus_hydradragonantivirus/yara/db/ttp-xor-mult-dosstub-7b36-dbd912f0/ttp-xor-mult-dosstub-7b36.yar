rule TTP_XOR_MULT_DOSStub_7b36 {
  strings:
    $key_7b36 = { 2f 5e [2] 5b 46 [2] 1c 44 [2] 5b 55 [2] 15 59 [2] 19 53 [2] 0e 58 [2] 15 16 [2] 28 }

  condition:
    any of them
}