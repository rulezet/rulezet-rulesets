rule TTP_XOR_MULT_DOSStub_7a39 {
  strings:
    $key_7a39 = { 2e 51 [2] 5a 49 [2] 1d 4b [2] 5a 5a [2] 14 56 [2] 18 5c [2] 0f 57 [2] 14 19 [2] 29 }

  condition:
    any of them
}