rule TTP_XOR_MULT_DOSStub_5471 {
  strings:
    $key_5471 = { 00 19 [2] 74 01 [2] 33 03 [2] 74 12 [2] 3a 1e [2] 36 14 [2] 21 1f [2] 3a 51 [2] 07 }

  condition:
    any of them
}