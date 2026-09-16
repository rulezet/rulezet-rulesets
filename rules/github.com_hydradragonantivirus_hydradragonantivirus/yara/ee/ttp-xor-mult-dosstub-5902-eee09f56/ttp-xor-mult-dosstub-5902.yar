rule TTP_XOR_MULT_DOSStub_5902 {
  strings:
    $key_5902 = { 0d 6a [2] 79 72 [2] 3e 70 [2] 79 61 [2] 37 6d [2] 3b 67 [2] 2c 6c [2] 37 22 [2] 0a }

  condition:
    any of them
}