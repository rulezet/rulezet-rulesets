rule TTP_XOR_MULT_DOSStub_7748 {
  strings:
    $key_7748 = { 23 20 [2] 57 38 [2] 10 3a [2] 57 2b [2] 19 27 [2] 15 2d [2] 02 26 [2] 19 68 [2] 24 }

  condition:
    any of them
}