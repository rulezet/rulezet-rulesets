rule TTP_XOR_MULT_DOSStub_2d07 {
  strings:
    $key_2d07 = { 79 6f [2] 0d 77 [2] 4a 75 [2] 0d 64 [2] 43 68 [2] 4f 62 [2] 58 69 [2] 43 27 [2] 7e }

  condition:
    any of them
}