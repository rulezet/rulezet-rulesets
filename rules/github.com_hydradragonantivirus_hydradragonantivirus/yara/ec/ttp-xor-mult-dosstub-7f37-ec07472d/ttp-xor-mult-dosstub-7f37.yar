rule TTP_XOR_MULT_DOSStub_7f37 {
  strings:
    $key_7f37 = { 2b 5f [2] 5f 47 [2] 18 45 [2] 5f 54 [2] 11 58 [2] 1d 52 [2] 0a 59 [2] 11 17 [2] 2c }

  condition:
    any of them
}