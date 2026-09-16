rule TTP_XOR_MULT_DOSStub_59f0 {
  strings:
    $key_59f0 = { 0d 98 [2] 79 80 [2] 3e 82 [2] 79 93 [2] 37 9f [2] 3b 95 [2] 2c 9e [2] 37 d0 [2] 0a }

  condition:
    any of them
}