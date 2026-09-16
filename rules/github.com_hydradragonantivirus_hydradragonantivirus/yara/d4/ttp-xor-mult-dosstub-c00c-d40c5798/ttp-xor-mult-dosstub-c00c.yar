rule TTP_XOR_MULT_DOSStub_c00c {
  strings:
    $key_c00c = { 94 64 [2] e0 7c [2] a7 7e [2] e0 6f [2] ae 63 [2] a2 69 [2] b5 62 [2] ae 2c [2] 93 }

  condition:
    any of them
}