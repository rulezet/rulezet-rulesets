rule TTP_XOR_MULT_DOSStub_5514 {
  strings:
    $key_5514 = { 01 7c [2] 75 64 [2] 32 66 [2] 75 77 [2] 3b 7b [2] 37 71 [2] 20 7a [2] 3b 34 [2] 06 }

  condition:
    any of them
}