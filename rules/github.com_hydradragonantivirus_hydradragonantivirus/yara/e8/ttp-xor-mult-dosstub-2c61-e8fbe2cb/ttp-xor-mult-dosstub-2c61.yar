rule TTP_XOR_MULT_DOSStub_2c61 {
  strings:
    $key_2c61 = { 78 09 [2] 0c 11 [2] 4b 13 [2] 0c 02 [2] 42 0e [2] 4e 04 [2] 59 0f [2] 42 41 [2] 7f }

  condition:
    any of them
}