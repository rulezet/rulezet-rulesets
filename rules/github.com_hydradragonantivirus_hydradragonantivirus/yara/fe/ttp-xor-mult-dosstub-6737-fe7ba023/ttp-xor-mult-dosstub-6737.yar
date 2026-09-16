rule TTP_XOR_MULT_DOSStub_6737 {
  strings:
    $key_6737 = { 33 5f [2] 47 47 [2] 00 45 [2] 47 54 [2] 09 58 [2] 05 52 [2] 12 59 [2] 09 17 [2] 34 }

  condition:
    any of them
}