rule TTP_XOR_MULT_DOSStub_c1e4 {
  strings:
    $key_c1e4 = { 95 8c [2] e1 94 [2] a6 96 [2] e1 87 [2] af 8b [2] a3 81 [2] b4 8a [2] af c4 [2] 92 }

  condition:
    any of them
}