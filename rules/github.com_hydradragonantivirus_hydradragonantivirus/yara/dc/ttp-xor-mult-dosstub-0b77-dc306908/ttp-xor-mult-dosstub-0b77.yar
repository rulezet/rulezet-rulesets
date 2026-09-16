rule TTP_XOR_MULT_DOSStub_0b77 {
  strings:
    $key_0b77 = { 5f 1f [2] 2b 07 [2] 6c 05 [2] 2b 14 [2] 65 18 [2] 69 12 [2] 7e 19 [2] 65 57 [2] 58 }

  condition:
    any of them
}