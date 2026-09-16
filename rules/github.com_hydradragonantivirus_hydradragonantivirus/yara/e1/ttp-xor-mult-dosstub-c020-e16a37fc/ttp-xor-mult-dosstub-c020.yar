rule TTP_XOR_MULT_DOSStub_c020 {
  strings:
    $key_c020 = { 94 48 [2] e0 50 [2] a7 52 [2] e0 43 [2] ae 4f [2] a2 45 [2] b5 4e [2] ae 00 [2] 93 }

  condition:
    any of them
}