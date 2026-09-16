rule TTP_XOR_MULT_DOSStub_59e7 {
  strings:
    $key_59e7 = { 0d 8f [2] 79 97 [2] 3e 95 [2] 79 84 [2] 37 88 [2] 3b 82 [2] 2c 89 [2] 37 c7 [2] 0a }

  condition:
    any of them
}