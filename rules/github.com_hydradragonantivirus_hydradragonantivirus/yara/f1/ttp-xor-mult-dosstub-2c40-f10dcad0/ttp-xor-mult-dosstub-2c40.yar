rule TTP_XOR_MULT_DOSStub_2c40 {
  strings:
    $key_2c40 = { 78 28 [2] 0c 30 [2] 4b 32 [2] 0c 23 [2] 42 2f [2] 4e 25 [2] 59 2e [2] 42 60 [2] 7f }

  condition:
    any of them
}