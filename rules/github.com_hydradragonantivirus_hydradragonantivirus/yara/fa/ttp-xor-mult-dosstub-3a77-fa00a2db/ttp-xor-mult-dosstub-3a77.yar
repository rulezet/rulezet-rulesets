rule TTP_XOR_MULT_DOSStub_3a77 {
  strings:
    $key_3a77 = { 6e 1f [2] 1a 07 [2] 5d 05 [2] 1a 14 [2] 54 18 [2] 58 12 [2] 4f 19 [2] 54 57 [2] 69 }

  condition:
    any of them
}