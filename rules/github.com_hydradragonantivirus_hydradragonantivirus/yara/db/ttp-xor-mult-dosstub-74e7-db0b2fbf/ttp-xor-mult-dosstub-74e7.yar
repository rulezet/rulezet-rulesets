rule TTP_XOR_MULT_DOSStub_74e7 {
  strings:
    $key_74e7 = { 20 8f [2] 54 97 [2] 13 95 [2] 54 84 [2] 1a 88 [2] 16 82 [2] 01 89 [2] 1a c7 [2] 27 }

  condition:
    any of them
}