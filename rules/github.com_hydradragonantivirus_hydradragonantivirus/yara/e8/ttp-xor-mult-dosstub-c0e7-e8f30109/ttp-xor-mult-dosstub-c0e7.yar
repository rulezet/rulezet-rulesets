rule TTP_XOR_MULT_DOSStub_c0e7 {
  strings:
    $key_c0e7 = { 94 8f [2] e0 97 [2] a7 95 [2] e0 84 [2] ae 88 [2] a2 82 [2] b5 89 [2] ae c7 [2] 93 }

  condition:
    any of them
}