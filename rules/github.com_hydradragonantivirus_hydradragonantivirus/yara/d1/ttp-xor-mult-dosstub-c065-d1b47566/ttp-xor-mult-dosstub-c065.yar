rule TTP_XOR_MULT_DOSStub_c065 {
  strings:
    $key_c065 = { 94 0d [2] e0 15 [2] a7 17 [2] e0 06 [2] ae 0a [2] a2 00 [2] b5 0b [2] ae 45 [2] 93 }

  condition:
    any of them
}