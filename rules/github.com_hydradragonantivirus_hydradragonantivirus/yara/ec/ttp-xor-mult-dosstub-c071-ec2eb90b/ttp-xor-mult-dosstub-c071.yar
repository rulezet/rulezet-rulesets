rule TTP_XOR_MULT_DOSStub_c071 {
  strings:
    $key_c071 = { 94 19 [2] e0 01 [2] a7 03 [2] e0 12 [2] ae 1e [2] a2 14 [2] b5 1f [2] ae 51 [2] 93 }

  condition:
    any of them
}