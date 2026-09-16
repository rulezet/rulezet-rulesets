rule TTP_XOR_MULT_DOSStub_5d57 {
  strings:
    $key_5d57 = { 09 3f [2] 7d 27 [2] 3a 25 [2] 7d 34 [2] 33 38 [2] 3f 32 [2] 28 39 [2] 33 77 [2] 0e }

  condition:
    any of them
}