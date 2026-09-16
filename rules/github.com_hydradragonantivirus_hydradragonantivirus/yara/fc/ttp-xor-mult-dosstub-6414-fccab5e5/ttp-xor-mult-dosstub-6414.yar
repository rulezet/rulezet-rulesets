rule TTP_XOR_MULT_DOSStub_6414 {
  strings:
    $key_6414 = { 30 7c [2] 44 64 [2] 03 66 [2] 44 77 [2] 0a 7b [2] 06 71 [2] 11 7a [2] 0a 34 [2] 37 }

  condition:
    any of them
}