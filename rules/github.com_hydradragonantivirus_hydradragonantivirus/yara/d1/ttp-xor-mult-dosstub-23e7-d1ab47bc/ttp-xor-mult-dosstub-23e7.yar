rule TTP_XOR_MULT_DOSStub_23e7 {
  strings:
    $key_23e7 = { 77 8f [2] 03 97 [2] 44 95 [2] 03 84 [2] 4d 88 [2] 41 82 [2] 56 89 [2] 4d c7 [2] 70 }

  condition:
    any of them
}