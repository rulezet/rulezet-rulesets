rule TTP_XOR_MULT_DOSStub_c054 {
  strings:
    $key_c054 = { 94 3c [2] e0 24 [2] a7 26 [2] e0 37 [2] ae 3b [2] a2 31 [2] b5 3a [2] ae 74 [2] 93 }

  condition:
    any of them
}