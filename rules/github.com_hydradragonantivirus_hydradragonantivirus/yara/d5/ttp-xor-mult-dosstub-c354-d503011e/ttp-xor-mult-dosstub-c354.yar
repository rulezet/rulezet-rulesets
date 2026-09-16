rule TTP_XOR_MULT_DOSStub_c354 {
  strings:
    $key_c354 = { 97 3c [2] e3 24 [2] a4 26 [2] e3 37 [2] ad 3b [2] a1 31 [2] b6 3a [2] ad 74 [2] 90 }

  condition:
    any of them
}