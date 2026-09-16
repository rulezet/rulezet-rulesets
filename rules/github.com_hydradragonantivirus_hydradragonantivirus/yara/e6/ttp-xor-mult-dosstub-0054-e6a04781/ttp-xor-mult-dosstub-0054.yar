rule TTP_XOR_MULT_DOSStub_0054 {
  strings:
    $key_0054 = { 54 3c [2] 20 24 [2] 67 26 [2] 20 37 [2] 6e 3b [2] 62 31 [2] 75 3a [2] 6e 74 [2] 53 }

  condition:
    any of them
}