rule TTP_XOR_MULT_DOSStub_c1e9 {
  strings:
    $key_c1e9 = { 95 81 [2] e1 99 [2] a6 9b [2] e1 8a [2] af 86 [2] a3 8c [2] b4 87 [2] af c9 [2] 92 }

  condition:
    any of them
}