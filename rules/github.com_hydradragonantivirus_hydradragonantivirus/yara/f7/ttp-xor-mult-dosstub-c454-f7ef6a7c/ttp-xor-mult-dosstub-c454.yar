rule TTP_XOR_MULT_DOSStub_c454 {
  strings:
    $key_c454 = { 90 3c [2] e4 24 [2] a3 26 [2] e4 37 [2] aa 3b [2] a6 31 [2] b1 3a [2] aa 74 [2] 97 }

  condition:
    any of them
}