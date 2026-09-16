rule TTP_XOR_MULT_DOSStub_4512 {
  strings:
    $key_4512 = { 11 7a [2] 65 62 [2] 22 60 [2] 65 71 [2] 2b 7d [2] 27 77 [2] 30 7c [2] 2b 32 [2] 16 }

  condition:
    any of them
}