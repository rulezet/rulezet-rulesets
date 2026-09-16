rule TTP_XOR_MULT_DOSStub_4218 {
  strings:
    $key_4218 = { 16 70 [2] 62 68 [2] 25 6a [2] 62 7b [2] 2c 77 [2] 20 7d [2] 37 76 [2] 2c 38 [2] 11 }

  condition:
    any of them
}