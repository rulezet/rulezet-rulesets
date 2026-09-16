rule TTP_XOR_MULT_DOSStub_4330 {
  strings:
    $key_4330 = { 17 58 [2] 63 40 [2] 24 42 [2] 63 53 [2] 2d 5f [2] 21 55 [2] 36 5e [2] 2d 10 [2] 10 }

  condition:
    any of them
}