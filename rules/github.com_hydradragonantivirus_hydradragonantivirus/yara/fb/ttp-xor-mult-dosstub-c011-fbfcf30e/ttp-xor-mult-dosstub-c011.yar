rule TTP_XOR_MULT_DOSStub_c011 {
  strings:
    $key_c011 = { 94 79 [2] e0 61 [2] a7 63 [2] e0 72 [2] ae 7e [2] a2 74 [2] b5 7f [2] ae 31 [2] 93 }

  condition:
    any of them
}