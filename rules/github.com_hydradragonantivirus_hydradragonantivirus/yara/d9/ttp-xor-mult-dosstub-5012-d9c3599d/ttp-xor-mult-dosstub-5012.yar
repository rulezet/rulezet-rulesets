rule TTP_XOR_MULT_DOSStub_5012 {
  strings:
    $key_5012 = { 04 7a [2] 70 62 [2] 37 60 [2] 70 71 [2] 3e 7d [2] 32 77 [2] 25 7c [2] 3e 32 [2] 03 }

  condition:
    any of them
}