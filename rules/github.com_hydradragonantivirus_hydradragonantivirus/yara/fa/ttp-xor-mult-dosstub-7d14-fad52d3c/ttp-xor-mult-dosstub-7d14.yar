rule TTP_XOR_MULT_DOSStub_7d14 {
  strings:
    $key_7d14 = { 29 7c [2] 5d 64 [2] 1a 66 [2] 5d 77 [2] 13 7b [2] 1f 71 [2] 08 7a [2] 13 34 [2] 2e }

  condition:
    any of them
}