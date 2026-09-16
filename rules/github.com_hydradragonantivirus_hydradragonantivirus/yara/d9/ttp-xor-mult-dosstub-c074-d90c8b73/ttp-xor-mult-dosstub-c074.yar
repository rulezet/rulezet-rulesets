rule TTP_XOR_MULT_DOSStub_c074 {
  strings:
    $key_c074 = { 94 1c [2] e0 04 [2] a7 06 [2] e0 17 [2] ae 1b [2] a2 11 [2] b5 1a [2] ae 54 [2] 93 }

  condition:
    any of them
}