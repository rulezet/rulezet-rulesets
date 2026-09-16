rule TTP_XOR_MULT_DOSStub_7fa9 {
  strings:
    $key_7fa9 = { 2b c1 [2] 5f d9 [2] 18 db [2] 5f ca [2] 11 c6 [2] 1d cc [2] 0a c7 [2] 11 89 [2] 2c }

  condition:
    any of them
}