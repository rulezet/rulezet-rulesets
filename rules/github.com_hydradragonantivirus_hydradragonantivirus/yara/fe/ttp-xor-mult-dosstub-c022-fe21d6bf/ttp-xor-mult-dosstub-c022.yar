rule TTP_XOR_MULT_DOSStub_c022 {
  strings:
    $key_c022 = { 94 4a [2] e0 52 [2] a7 50 [2] e0 41 [2] ae 4d [2] a2 47 [2] b5 4c [2] ae 02 [2] 93 }

  condition:
    any of them
}