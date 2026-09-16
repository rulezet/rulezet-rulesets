rule TTP_XOR_MULT_DOSStub_5d07 {
  strings:
    $key_5d07 = { 09 6f [2] 7d 77 [2] 3a 75 [2] 7d 64 [2] 33 68 [2] 3f 62 [2] 28 69 [2] 33 27 [2] 0e }

  condition:
    any of them
}