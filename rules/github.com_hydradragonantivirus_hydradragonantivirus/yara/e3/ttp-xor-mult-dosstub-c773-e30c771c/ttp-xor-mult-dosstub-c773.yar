rule TTP_XOR_MULT_DOSStub_c773 {
  strings:
    $key_c773 = { 93 1b [2] e7 03 [2] a0 01 [2] e7 10 [2] a9 1c [2] a5 16 [2] b2 1d [2] a9 53 [2] 94 }

  condition:
    any of them
}