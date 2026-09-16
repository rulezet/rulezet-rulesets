rule TTP_XOR_MULT_DOSStub_59f8 {
  strings:
    $key_59f8 = { 0d 90 [2] 79 88 [2] 3e 8a [2] 79 9b [2] 37 97 [2] 3b 9d [2] 2c 96 [2] 37 d8 [2] 0a }

  condition:
    any of them
}