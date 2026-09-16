rule TTP_XOR_MULT_DOSStub_c587 {
  strings:
    $key_c587 = { 91 ef [2] e5 f7 [2] a2 f5 [2] e5 e4 [2] ab e8 [2] a7 e2 [2] b0 e9 [2] ab a7 [2] 96 }

  condition:
    any of them
}