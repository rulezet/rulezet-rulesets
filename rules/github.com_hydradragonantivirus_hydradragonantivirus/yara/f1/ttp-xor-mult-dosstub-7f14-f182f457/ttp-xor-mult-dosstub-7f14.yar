rule TTP_XOR_MULT_DOSStub_7f14 {
  strings:
    $key_7f14 = { 2b 7c [2] 5f 64 [2] 18 66 [2] 5f 77 [2] 11 7b [2] 1d 71 [2] 0a 7a [2] 11 34 [2] 2c }

  condition:
    any of them
}