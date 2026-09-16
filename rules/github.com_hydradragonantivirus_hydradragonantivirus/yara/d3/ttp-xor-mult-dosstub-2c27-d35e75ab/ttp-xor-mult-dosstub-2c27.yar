rule TTP_XOR_MULT_DOSStub_2c27 {
  strings:
    $key_2c27 = { 78 4f [2] 0c 57 [2] 4b 55 [2] 0c 44 [2] 42 48 [2] 4e 42 [2] 59 49 [2] 42 07 [2] 7f }

  condition:
    any of them
}