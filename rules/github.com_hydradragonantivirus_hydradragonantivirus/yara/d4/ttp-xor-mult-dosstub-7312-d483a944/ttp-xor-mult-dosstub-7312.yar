rule TTP_XOR_MULT_DOSStub_7312 {
  strings:
    $key_7312 = { 27 7a [2] 53 62 [2] 14 60 [2] 53 71 [2] 1d 7d [2] 11 77 [2] 06 7c [2] 1d 32 [2] 20 }

  condition:
    any of them
}