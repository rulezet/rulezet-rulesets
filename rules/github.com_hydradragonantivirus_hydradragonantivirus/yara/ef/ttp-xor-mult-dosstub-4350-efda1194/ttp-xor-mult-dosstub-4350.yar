rule TTP_XOR_MULT_DOSStub_4350 {
  strings:
    $key_4350 = { 17 38 [2] 63 20 [2] 24 22 [2] 63 33 [2] 2d 3f [2] 21 35 [2] 36 3e [2] 2d 70 [2] 10 }

  condition:
    any of them
}