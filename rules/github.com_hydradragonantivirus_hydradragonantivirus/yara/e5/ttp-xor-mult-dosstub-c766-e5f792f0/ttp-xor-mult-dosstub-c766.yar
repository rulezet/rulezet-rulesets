rule TTP_XOR_MULT_DOSStub_c766 {
  strings:
    $key_c766 = { 93 0e [2] e7 16 [2] a0 14 [2] e7 05 [2] a9 09 [2] a5 03 [2] b2 08 [2] a9 46 [2] 94 }

  condition:
    any of them
}