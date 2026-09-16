rule TTP_XOR_MULT_DOSStub_4607 {
  strings:
    $key_4607 = { 12 6f [2] 66 77 [2] 21 75 [2] 66 64 [2] 28 68 [2] 24 62 [2] 33 69 [2] 28 27 [2] 15 }

  condition:
    any of them
}