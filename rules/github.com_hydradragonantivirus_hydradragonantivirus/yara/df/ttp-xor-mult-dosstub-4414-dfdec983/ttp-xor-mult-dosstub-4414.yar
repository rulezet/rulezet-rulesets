rule TTP_XOR_MULT_DOSStub_4414 {
  strings:
    $key_4414 = { 10 7c [2] 64 64 [2] 23 66 [2] 64 77 [2] 2a 7b [2] 26 71 [2] 31 7a [2] 2a 34 [2] 17 }

  condition:
    any of them
}