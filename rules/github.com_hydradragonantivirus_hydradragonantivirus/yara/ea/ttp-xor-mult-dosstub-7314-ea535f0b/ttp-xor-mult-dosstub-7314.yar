rule TTP_XOR_MULT_DOSStub_7314 {
  strings:
    $key_7314 = { 27 7c [2] 53 64 [2] 14 66 [2] 53 77 [2] 1d 7b [2] 11 71 [2] 06 7a [2] 1d 34 [2] 20 }

  condition:
    any of them
}