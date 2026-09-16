rule TTP_XOR_MULT_DOSStub_c007 {
  strings:
    $key_c007 = { 94 6f [2] e0 77 [2] a7 75 [2] e0 64 [2] ae 68 [2] a2 62 [2] b5 69 [2] ae 27 [2] 93 }

  condition:
    any of them
}