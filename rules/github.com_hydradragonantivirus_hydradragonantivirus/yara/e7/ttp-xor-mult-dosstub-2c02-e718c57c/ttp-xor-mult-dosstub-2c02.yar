rule TTP_XOR_MULT_DOSStub_2c02 {
  strings:
    $key_2c02 = { 78 6a [2] 0c 72 [2] 4b 70 [2] 0c 61 [2] 42 6d [2] 4e 67 [2] 59 6c [2] 42 22 [2] 7f }

  condition:
    any of them
}