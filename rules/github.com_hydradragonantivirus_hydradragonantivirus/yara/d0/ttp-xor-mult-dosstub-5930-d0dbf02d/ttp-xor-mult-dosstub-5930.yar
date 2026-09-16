rule TTP_XOR_MULT_DOSStub_5930 {
  strings:
    $key_5930 = { 0d 58 [2] 79 40 [2] 3e 42 [2] 79 53 [2] 37 5f [2] 3b 55 [2] 2c 5e [2] 37 10 [2] 0a }

  condition:
    any of them
}