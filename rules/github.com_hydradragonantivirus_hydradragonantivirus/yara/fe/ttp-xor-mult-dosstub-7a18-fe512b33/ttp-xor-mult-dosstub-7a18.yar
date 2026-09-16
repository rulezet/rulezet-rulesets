rule TTP_XOR_MULT_DOSStub_7a18 {
  strings:
    $key_7a18 = { 2e 70 [2] 5a 68 [2] 1d 6a [2] 5a 7b [2] 14 77 [2] 18 7d [2] 0f 76 [2] 14 38 [2] 29 }

  condition:
    any of them
}