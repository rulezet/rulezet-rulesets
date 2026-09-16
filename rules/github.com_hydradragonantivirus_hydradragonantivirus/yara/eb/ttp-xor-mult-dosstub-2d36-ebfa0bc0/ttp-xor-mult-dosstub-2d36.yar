rule TTP_XOR_MULT_DOSStub_2d36 {
  strings:
    $key_2d36 = { 79 5e [2] 0d 46 [2] 4a 44 [2] 0d 55 [2] 43 59 [2] 4f 53 [2] 58 58 [2] 43 16 [2] 7e }

  condition:
    any of them
}