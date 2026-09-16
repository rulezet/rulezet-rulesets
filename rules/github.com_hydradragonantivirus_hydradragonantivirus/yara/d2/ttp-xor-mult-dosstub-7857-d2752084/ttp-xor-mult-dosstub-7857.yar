rule TTP_XOR_MULT_DOSStub_7857 {
  strings:
    $key_7857 = { 2c 3f [2] 58 27 [2] 1f 25 [2] 58 34 [2] 16 38 [2] 1a 32 [2] 0d 39 [2] 16 77 [2] 2b }

  condition:
    any of them
}