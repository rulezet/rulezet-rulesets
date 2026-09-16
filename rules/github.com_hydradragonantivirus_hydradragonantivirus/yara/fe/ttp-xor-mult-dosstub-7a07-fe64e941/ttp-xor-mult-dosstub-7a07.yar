rule TTP_XOR_MULT_DOSStub_7a07 {
  strings:
    $key_7a07 = { 2e 6f [2] 5a 77 [2] 1d 75 [2] 5a 64 [2] 14 68 [2] 18 62 [2] 0f 69 [2] 14 27 [2] 29 }

  condition:
    any of them
}