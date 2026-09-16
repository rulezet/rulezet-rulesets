rule TTP_XOR_MULT_DOSStub_5614 {
  strings:
    $key_5614 = { 02 7c [2] 76 64 [2] 31 66 [2] 76 77 [2] 38 7b [2] 34 71 [2] 23 7a [2] 38 34 [2] 05 }

  condition:
    any of them
}