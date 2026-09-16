rule TTP_XOR_MULT_DOSStub_c734 {
  strings:
    $key_c734 = { 93 5c [2] e7 44 [2] a0 46 [2] e7 57 [2] a9 5b [2] a5 51 [2] b2 5a [2] a9 14 [2] 94 }

  condition:
    any of them
}