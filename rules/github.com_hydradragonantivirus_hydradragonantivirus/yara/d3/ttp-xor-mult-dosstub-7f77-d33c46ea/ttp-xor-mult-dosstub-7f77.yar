rule TTP_XOR_MULT_DOSStub_7f77 {
  strings:
    $key_7f77 = { 2b 1f [2] 5f 07 [2] 18 05 [2] 5f 14 [2] 11 18 [2] 1d 12 [2] 0a 19 [2] 11 57 [2] 2c }

  condition:
    any of them
}