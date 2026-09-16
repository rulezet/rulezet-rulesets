rule TTP_XOR_MULT_DOSStub_0754 {
  strings:
    $key_0754 = { 53 3c [2] 27 24 [2] 60 26 [2] 27 37 [2] 69 3b [2] 65 31 [2] 72 3a [2] 69 74 [2] 54 }

  condition:
    any of them
}