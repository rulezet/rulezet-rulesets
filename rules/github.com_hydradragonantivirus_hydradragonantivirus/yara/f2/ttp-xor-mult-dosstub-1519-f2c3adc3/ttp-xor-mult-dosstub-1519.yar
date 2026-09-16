rule TTP_XOR_MULT_DOSStub_1519 {
  strings:
    $key_1519 = { 41 71 [2] 35 69 [2] 72 6b [2] 35 7a [2] 7b 76 [2] 77 7c [2] 60 77 [2] 7b 39 [2] 46 }

  condition:
    any of them
}