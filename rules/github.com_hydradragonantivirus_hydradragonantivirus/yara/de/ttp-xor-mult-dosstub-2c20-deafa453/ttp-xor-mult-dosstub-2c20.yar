rule TTP_XOR_MULT_DOSStub_2c20 {
  strings:
    $key_2c20 = { 78 48 [2] 0c 50 [2] 4b 52 [2] 0c 43 [2] 42 4f [2] 4e 45 [2] 59 4e [2] 42 00 [2] 7f }

  condition:
    any of them
}