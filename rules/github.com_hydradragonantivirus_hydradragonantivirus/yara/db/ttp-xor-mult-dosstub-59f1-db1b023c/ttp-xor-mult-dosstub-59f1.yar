rule TTP_XOR_MULT_DOSStub_59f1 {
  strings:
    $key_59f1 = { 0d 99 [2] 79 81 [2] 3e 83 [2] 79 92 [2] 37 9e [2] 3b 94 [2] 2c 9f [2] 37 d1 [2] 0a }

  condition:
    any of them
}