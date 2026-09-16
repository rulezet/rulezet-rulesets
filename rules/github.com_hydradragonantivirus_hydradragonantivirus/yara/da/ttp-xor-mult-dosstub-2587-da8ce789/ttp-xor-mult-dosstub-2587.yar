rule TTP_XOR_MULT_DOSStub_2587 {
  strings:
    $key_2587 = { 71 ef [2] 05 f7 [2] 42 f5 [2] 05 e4 [2] 4b e8 [2] 47 e2 [2] 50 e9 [2] 4b a7 [2] 76 }

  condition:
    any of them
}