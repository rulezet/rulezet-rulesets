rule TTP_XOR_MULT_DOSStub_4a27 {
  strings:
    $key_4a27 = { 1e 4f [2] 6a 57 [2] 2d 55 [2] 6a 44 [2] 24 48 [2] 28 42 [2] 3f 49 [2] 24 07 [2] 19 }

  condition:
    any of them
}