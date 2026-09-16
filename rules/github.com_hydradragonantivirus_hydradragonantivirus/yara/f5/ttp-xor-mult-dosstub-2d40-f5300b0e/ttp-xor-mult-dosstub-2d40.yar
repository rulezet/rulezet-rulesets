rule TTP_XOR_MULT_DOSStub_2d40 {
  strings:
    $key_2d40 = { 79 28 [2] 0d 30 [2] 4a 32 [2] 0d 23 [2] 43 2f [2] 4f 25 [2] 58 2e [2] 43 60 [2] 7e }

  condition:
    any of them
}