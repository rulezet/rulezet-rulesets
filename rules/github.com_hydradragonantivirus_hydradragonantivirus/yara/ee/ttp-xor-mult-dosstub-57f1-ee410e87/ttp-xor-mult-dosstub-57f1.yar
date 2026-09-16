rule TTP_XOR_MULT_DOSStub_57f1 {
  strings:
    $key_57f1 = { 03 99 [2] 77 81 [2] 30 83 [2] 77 92 [2] 39 9e [2] 35 94 [2] 22 9f [2] 39 d1 [2] 04 }

  condition:
    any of them
}