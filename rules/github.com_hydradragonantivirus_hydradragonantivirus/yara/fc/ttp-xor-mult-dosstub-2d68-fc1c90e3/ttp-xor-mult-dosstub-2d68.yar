rule TTP_XOR_MULT_DOSStub_2d68 {
  strings:
    $key_2d68 = { 79 00 [2] 0d 18 [2] 4a 1a [2] 0d 0b [2] 43 07 [2] 4f 0d [2] 58 06 [2] 43 48 [2] 7e }

  condition:
    any of them
}