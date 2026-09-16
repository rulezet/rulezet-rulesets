rule TTP_XOR_MULT_DOSStub_c290 {
  strings:
    $key_c290 = { 96 f8 [2] e2 e0 [2] a5 e2 [2] e2 f3 [2] ac ff [2] a0 f5 [2] b7 fe [2] ac b0 [2] 91 }

  condition:
    any of them
}