rule TTP_XOR_MULT_DOSStub_1a77 {
  strings:
    $key_1a77 = { 4e 1f [2] 3a 07 [2] 7d 05 [2] 3a 14 [2] 74 18 [2] 78 12 [2] 6f 19 [2] 74 57 [2] 49 }

  condition:
    any of them
}