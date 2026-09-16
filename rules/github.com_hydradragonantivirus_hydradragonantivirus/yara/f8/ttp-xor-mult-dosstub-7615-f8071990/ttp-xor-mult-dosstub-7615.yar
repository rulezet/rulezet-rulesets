rule TTP_XOR_MULT_DOSStub_7615 {
  strings:
    $key_7615 = { 22 7d [2] 56 65 [2] 11 67 [2] 56 76 [2] 18 7a [2] 14 70 [2] 03 7b [2] 18 35 [2] 25 }

  condition:
    any of them
}