rule TTP_XOR_MULT_DOSStub_5781 {
  strings:
    $key_5781 = { 03 e9 [2] 77 f1 [2] 30 f3 [2] 77 e2 [2] 39 ee [2] 35 e4 [2] 22 ef [2] 39 a1 [2] 04 }

  condition:
    any of them
}