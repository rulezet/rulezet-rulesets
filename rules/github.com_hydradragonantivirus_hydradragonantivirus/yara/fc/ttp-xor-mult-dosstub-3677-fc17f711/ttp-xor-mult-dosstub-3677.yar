rule TTP_XOR_MULT_DOSStub_3677 {
  strings:
    $key_3677 = { 62 1f [2] 16 07 [2] 51 05 [2] 16 14 [2] 58 18 [2] 54 12 [2] 43 19 [2] 58 57 [2] 65 }

  condition:
    any of them
}