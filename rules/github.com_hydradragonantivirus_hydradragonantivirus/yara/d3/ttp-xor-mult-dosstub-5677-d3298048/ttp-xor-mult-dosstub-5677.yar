rule TTP_XOR_MULT_DOSStub_5677 {
  strings:
    $key_5677 = { 02 1f [2] 76 07 [2] 31 05 [2] 76 14 [2] 38 18 [2] 34 12 [2] 23 19 [2] 38 57 [2] 05 }

  condition:
    any of them
}