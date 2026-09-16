rule TTP_XOR_MULT_DOSStub_2d57 {
  strings:
    $key_2d57 = { 79 3f [2] 0d 27 [2] 4a 25 [2] 0d 34 [2] 43 38 [2] 4f 32 [2] 58 39 [2] 43 77 [2] 7e }

  condition:
    any of them
}