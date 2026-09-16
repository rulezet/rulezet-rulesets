rule TTP_XOR_MULT_DOSStub_7519 {
  strings:
    $key_7519 = { 21 71 [2] 55 69 [2] 12 6b [2] 55 7a [2] 1b 76 [2] 17 7c [2] 00 77 [2] 1b 39 [2] 26 }

  condition:
    any of them
}