rule TTP_XOR_MULT_DOSStub_0819 {
  strings:
    $key_0819 = { 5c 71 [2] 28 69 [2] 6f 6b [2] 28 7a [2] 66 76 [2] 6a 7c [2] 7d 77 [2] 66 39 [2] 5b }

  condition:
    any of them
}