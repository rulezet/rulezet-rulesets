rule TTP_XOR_MULT_DOSStub_c03d {
  strings:
    $key_c03d = { 94 55 [2] e0 4d [2] a7 4f [2] e0 5e [2] ae 52 [2] a2 58 [2] b5 53 [2] ae 1d [2] 93 }

  condition:
    any of them
}