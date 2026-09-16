rule TTP_XOR_MULT_DOSStub_59f5 {
  strings:
    $key_59f5 = { 0d 9d [2] 79 85 [2] 3e 87 [2] 79 96 [2] 37 9a [2] 3b 90 [2] 2c 9b [2] 37 d5 [2] 0a }

  condition:
    any of them
}