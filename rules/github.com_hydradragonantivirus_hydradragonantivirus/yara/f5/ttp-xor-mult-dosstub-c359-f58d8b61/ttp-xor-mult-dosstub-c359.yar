rule TTP_XOR_MULT_DOSStub_c359 {
  strings:
    $key_c359 = { 97 31 [2] e3 29 [2] a4 2b [2] e3 3a [2] ad 36 [2] a1 3c [2] b6 37 [2] ad 79 [2] 90 }

  condition:
    any of them
}