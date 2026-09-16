rule TTP_XOR_MULT_DOSStub_c297 {
  strings:
    $key_c297 = { 96 ff [2] e2 e7 [2] a5 e5 [2] e2 f4 [2] ac f8 [2] a0 f2 [2] b7 f9 [2] ac b7 [2] 91 }

  condition:
    any of them
}