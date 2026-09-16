rule TTP_XOR_MULT_DOSStub_5414 {
  strings:
    $key_5414 = { 00 7c [2] 74 64 [2] 33 66 [2] 74 77 [2] 3a 7b [2] 36 71 [2] 21 7a [2] 3a 34 [2] 07 }

  condition:
    any of them
}