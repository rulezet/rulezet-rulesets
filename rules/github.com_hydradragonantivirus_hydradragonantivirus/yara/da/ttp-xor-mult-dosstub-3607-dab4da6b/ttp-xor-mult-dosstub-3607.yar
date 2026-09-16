rule TTP_XOR_MULT_DOSStub_3607 {
  strings:
    $key_3607 = { 62 6f [2] 16 77 [2] 51 75 [2] 16 64 [2] 58 68 [2] 54 62 [2] 43 69 [2] 58 27 [2] 65 }

  condition:
    any of them
}