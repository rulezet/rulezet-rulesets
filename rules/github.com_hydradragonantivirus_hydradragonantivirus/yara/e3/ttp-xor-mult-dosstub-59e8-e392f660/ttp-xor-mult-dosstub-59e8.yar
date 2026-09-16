rule TTP_XOR_MULT_DOSStub_59e8 {
  strings:
    $key_59e8 = { 0d 80 [2] 79 98 [2] 3e 9a [2] 79 8b [2] 37 87 [2] 3b 8d [2] 2c 86 [2] 37 c8 [2] 0a }

  condition:
    any of them
}