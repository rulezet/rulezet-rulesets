rule TTP_XOR_MULT_DOSStub_7f60 {
  strings:
    $key_7f60 = { 2b 08 [2] 5f 10 [2] 18 12 [2] 5f 03 [2] 11 0f [2] 1d 05 [2] 0a 0e [2] 11 40 [2] 2c }

  condition:
    any of them
}