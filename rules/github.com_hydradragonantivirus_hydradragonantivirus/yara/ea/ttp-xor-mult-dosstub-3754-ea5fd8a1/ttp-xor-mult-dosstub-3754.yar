rule TTP_XOR_MULT_DOSStub_3754 {
  strings:
    $key_3754 = { 63 3c [2] 17 24 [2] 50 26 [2] 17 37 [2] 59 3b [2] 55 31 [2] 42 3a [2] 59 74 [2] 64 }

  condition:
    any of them
}