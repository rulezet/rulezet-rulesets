rule TTP_XOR_MULT_DOSStub_7f12 {
  strings:
    $key_7f12 = { 2b 7a [2] 5f 62 [2] 18 60 [2] 5f 71 [2] 11 7d [2] 1d 77 [2] 0a 7c [2] 11 32 [2] 2c }

  condition:
    any of them
}