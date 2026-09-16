rule TTP_XOR_MULT_DOSStub_c586 {
  strings:
    $key_c586 = { 91 ee [2] e5 f6 [2] a2 f4 [2] e5 e5 [2] ab e9 [2] a7 e3 [2] b0 e8 [2] ab a6 [2] 96 }

  condition:
    any of them
}