rule TTP_XOR_MULT_DOSStub_c097 {
  strings:
    $key_c097 = { 94 ff [2] e0 e7 [2] a7 e5 [2] e0 f4 [2] ae f8 [2] a2 f2 [2] b5 f9 [2] ae b7 [2] 93 }

  condition:
    any of them
}