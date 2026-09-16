rule TTP_XOR_MULT_DOSStub_7419 {
  strings:
    $key_7419 = { 20 71 [2] 54 69 [2] 13 6b [2] 54 7a [2] 1a 76 [2] 16 7c [2] 01 77 [2] 1a 39 [2] 27 }

  condition:
    any of them
}