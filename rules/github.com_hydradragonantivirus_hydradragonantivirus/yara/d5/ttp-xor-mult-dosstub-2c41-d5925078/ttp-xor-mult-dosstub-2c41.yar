rule TTP_XOR_MULT_DOSStub_2c41 {
  strings:
    $key_2c41 = { 78 29 [2] 0c 31 [2] 4b 33 [2] 0c 22 [2] 42 2e [2] 4e 24 [2] 59 2f [2] 42 61 [2] 7f }

  condition:
    any of them
}