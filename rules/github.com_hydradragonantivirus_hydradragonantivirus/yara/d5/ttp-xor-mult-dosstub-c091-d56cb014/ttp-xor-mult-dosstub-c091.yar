rule TTP_XOR_MULT_DOSStub_c091 {
  strings:
    $key_c091 = { 94 f9 [2] e0 e1 [2] a7 e3 [2] e0 f2 [2] ae fe [2] a2 f4 [2] b5 ff [2] ae b1 [2] 93 }

  condition:
    any of them
}