rule TTP_XOR_MULT_DOSStub_2519 {
  strings:
    $key_2519 = { 71 71 [2] 05 69 [2] 42 6b [2] 05 7a [2] 4b 76 [2] 47 7c [2] 50 77 [2] 4b 39 [2] 76 }

  condition:
    any of them
}