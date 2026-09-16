rule TTP_XOR_MULT_DOSStub_2c62 {
  strings:
    $key_2c62 = { 78 0a [2] 0c 12 [2] 4b 10 [2] 0c 01 [2] 42 0d [2] 4e 07 [2] 59 0c [2] 42 42 [2] 7f }

  condition:
    any of them
}