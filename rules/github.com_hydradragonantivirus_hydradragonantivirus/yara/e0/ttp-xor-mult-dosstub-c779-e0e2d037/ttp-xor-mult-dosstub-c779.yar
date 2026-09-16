rule TTP_XOR_MULT_DOSStub_c779 {
  strings:
    $key_c779 = { 93 11 [2] e7 09 [2] a0 0b [2] e7 1a [2] a9 16 [2] a5 1c [2] b2 17 [2] a9 59 [2] 94 }

  condition:
    any of them
}