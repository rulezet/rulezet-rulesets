rule TTP_XOR_MULT_DOSStub_2387 {
  strings:
    $key_2387 = { 77 ef [2] 03 f7 [2] 44 f5 [2] 03 e4 [2] 4d e8 [2] 41 e2 [2] 56 e9 [2] 4d a7 [2] 70 }

  condition:
    any of them
}