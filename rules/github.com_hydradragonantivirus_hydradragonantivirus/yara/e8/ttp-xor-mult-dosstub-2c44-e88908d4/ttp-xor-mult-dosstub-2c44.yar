rule TTP_XOR_MULT_DOSStub_2c44 {
  strings:
    $key_2c44 = { 78 2c [2] 0c 34 [2] 4b 36 [2] 0c 27 [2] 42 2b [2] 4e 21 [2] 59 2a [2] 42 64 [2] 7f }

  condition:
    any of them
}