rule TTP_XOR_MULT_DOSStub_5936 {
  strings:
    $key_5936 = { 0d 5e [2] 79 46 [2] 3e 44 [2] 79 55 [2] 37 59 [2] 3b 53 [2] 2c 58 [2] 37 16 [2] 0a }

  condition:
    any of them
}