rule TTP_XOR_MULT_DOSStub_c659 {
  strings:
    $key_c659 = { 92 31 [2] e6 29 [2] a1 2b [2] e6 3a [2] a8 36 [2] a4 3c [2] b3 37 [2] a8 79 [2] 95 }

  condition:
    any of them
}