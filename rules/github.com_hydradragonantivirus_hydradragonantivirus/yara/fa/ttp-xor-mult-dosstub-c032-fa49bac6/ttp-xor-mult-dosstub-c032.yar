rule TTP_XOR_MULT_DOSStub_c032 {
  strings:
    $key_c032 = { 94 5a [2] e0 42 [2] a7 40 [2] e0 51 [2] ae 5d [2] a2 57 [2] b5 5c [2] ae 12 [2] 93 }

  condition:
    any of them
}