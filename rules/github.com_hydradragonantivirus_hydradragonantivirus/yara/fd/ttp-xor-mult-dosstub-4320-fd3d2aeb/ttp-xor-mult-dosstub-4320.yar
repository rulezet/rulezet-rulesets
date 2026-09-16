rule TTP_XOR_MULT_DOSStub_4320 {
  strings:
    $key_4320 = { 17 48 [2] 63 50 [2] 24 52 [2] 63 43 [2] 2d 4f [2] 21 45 [2] 36 4e [2] 2d 00 [2] 10 }

  condition:
    any of them
}