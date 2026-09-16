rule TTP_XOR_MULT_DOSStub_5407 {
  strings:
    $key_5407 = { 00 6f [2] 74 77 [2] 33 75 [2] 74 64 [2] 3a 68 [2] 36 62 [2] 21 69 [2] 3a 27 [2] 07 }

  condition:
    any of them
}