rule TTP_XOR_MULT_DOSStub_c044 {
  strings:
    $key_c044 = { 94 2c [2] e0 34 [2] a7 36 [2] e0 27 [2] ae 2b [2] a2 21 [2] b5 2a [2] ae 64 [2] 93 }

  condition:
    any of them
}