rule TTP_XOR_MULT_DOSStub_2c06 {
  strings:
    $key_2c06 = { 78 6e [2] 0c 76 [2] 4b 74 [2] 0c 65 [2] 42 69 [2] 4e 63 [2] 59 68 [2] 42 26 [2] 7f }

  condition:
    any of them
}