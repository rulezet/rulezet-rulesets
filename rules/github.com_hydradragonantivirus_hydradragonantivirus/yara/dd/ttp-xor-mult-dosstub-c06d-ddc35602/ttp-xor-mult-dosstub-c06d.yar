rule TTP_XOR_MULT_DOSStub_c06d {
  strings:
    $key_c06d = { 94 05 [2] e0 1d [2] a7 1f [2] e0 0e [2] ae 02 [2] a2 08 [2] b5 03 [2] ae 4d [2] 93 }

  condition:
    any of them
}