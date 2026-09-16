rule TTP_XOR_MULT_DOSStub_7fe7 {
  strings:
    $key_7fe7 = { 2b 8f [2] 5f 97 [2] 18 95 [2] 5f 84 [2] 11 88 [2] 1d 82 [2] 0a 89 [2] 11 c7 [2] 2c }

  condition:
    any of them
}