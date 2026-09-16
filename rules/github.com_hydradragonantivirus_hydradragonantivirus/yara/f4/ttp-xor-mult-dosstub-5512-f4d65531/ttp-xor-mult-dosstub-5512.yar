rule TTP_XOR_MULT_DOSStub_5512 {
  strings:
    $key_5512 = { 01 7a [2] 75 62 [2] 32 60 [2] 75 71 [2] 3b 7d [2] 37 77 [2] 20 7c [2] 3b 32 [2] 06 }

  condition:
    any of them
}