rule TTP_XOR_MULT_DOSStub_4012 {
  strings:
    $key_4012 = { 14 7a [2] 60 62 [2] 27 60 [2] 60 71 [2] 2e 7d [2] 22 77 [2] 35 7c [2] 2e 32 [2] 13 }

  condition:
    any of them
}