rule TTP_XOR_MULT_DOSStub_59e2 {
  strings:
    $key_59e2 = { 0d 8a [2] 79 92 [2] 3e 90 [2] 79 81 [2] 37 8d [2] 3b 87 [2] 2c 8c [2] 37 c2 [2] 0a }

  condition:
    any of them
}