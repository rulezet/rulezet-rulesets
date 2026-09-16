rule TTP_XOR_MULT_DOSStub_5787 {
  strings:
    $key_5787 = { 03 ef [2] 77 f7 [2] 30 f5 [2] 77 e4 [2] 39 e8 [2] 35 e2 [2] 22 e9 [2] 39 a7 [2] 04 }

  condition:
    any of them
}