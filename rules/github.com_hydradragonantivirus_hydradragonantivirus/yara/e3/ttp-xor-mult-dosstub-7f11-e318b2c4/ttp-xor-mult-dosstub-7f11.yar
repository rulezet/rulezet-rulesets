rule TTP_XOR_MULT_DOSStub_7f11 {
  strings:
    $key_7f11 = { 2b 79 [2] 5f 61 [2] 18 63 [2] 5f 72 [2] 11 7e [2] 1d 74 [2] 0a 7f [2] 11 31 [2] 2c }

  condition:
    any of them
}