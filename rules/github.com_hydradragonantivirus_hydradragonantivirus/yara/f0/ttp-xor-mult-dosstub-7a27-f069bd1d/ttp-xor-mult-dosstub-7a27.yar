rule TTP_XOR_MULT_DOSStub_7a27 {
  strings:
    $key_7a27 = { 2e 4f [2] 5a 57 [2] 1d 55 [2] 5a 44 [2] 14 48 [2] 18 42 [2] 0f 49 [2] 14 07 [2] 29 }

  condition:
    any of them
}