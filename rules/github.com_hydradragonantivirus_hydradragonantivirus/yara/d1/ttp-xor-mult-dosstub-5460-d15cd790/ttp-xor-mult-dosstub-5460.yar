rule TTP_XOR_MULT_DOSStub_5460 {
  strings:
    $key_5460 = { 00 08 [2] 74 10 [2] 33 12 [2] 74 03 [2] 3a 0f [2] 36 05 [2] 21 0e [2] 3a 40 [2] 07 }

  condition:
    any of them
}