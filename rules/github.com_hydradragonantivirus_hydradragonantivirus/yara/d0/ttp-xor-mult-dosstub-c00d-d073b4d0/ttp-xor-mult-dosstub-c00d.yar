rule TTP_XOR_MULT_DOSStub_c00d {
  strings:
    $key_c00d = { 94 65 [2] e0 7d [2] a7 7f [2] e0 6e [2] ae 62 [2] a2 68 [2] b5 63 [2] ae 2d [2] 93 }

  condition:
    any of them
}