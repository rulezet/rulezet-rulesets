rule TTP_XOR_MULT_DOSStub_c063 {
  strings:
    $key_c063 = { 94 0b [2] e0 13 [2] a7 11 [2] e0 00 [2] ae 0c [2] a2 06 [2] b5 0d [2] ae 43 [2] 93 }

  condition:
    any of them
}