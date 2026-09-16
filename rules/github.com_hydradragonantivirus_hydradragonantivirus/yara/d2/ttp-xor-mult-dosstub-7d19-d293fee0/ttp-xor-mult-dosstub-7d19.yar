rule TTP_XOR_MULT_DOSStub_7d19 {
  strings:
    $key_7d19 = { 29 71 [2] 5d 69 [2] 1a 6b [2] 5d 7a [2] 13 76 [2] 1f 7c [2] 08 77 [2] 13 39 [2] 2e }

  condition:
    any of them
}