rule TTP_XOR_MULT_DOSStub_3519 {
  strings:
    $key_3519 = { 61 71 [2] 15 69 [2] 52 6b [2] 15 7a [2] 5b 76 [2] 57 7c [2] 40 77 [2] 5b 39 [2] 66 }

  condition:
    any of them
}