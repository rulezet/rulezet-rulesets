rule TTP_XOR_MULT_DOSStub_7d07 {
  strings:
    $key_7d07 = { 29 6f [2] 5d 77 [2] 1a 75 [2] 5d 64 [2] 13 68 [2] 1f 62 [2] 08 69 [2] 13 27 [2] 2e }

  condition:
    any of them
}