rule TTP_XOR_MULT_DOSStub_c1f5 {
  strings:
    $key_c1f5 = { 95 9d [2] e1 85 [2] a6 87 [2] e1 96 [2] af 9a [2] a3 90 [2] b4 9b [2] af d5 [2] 92 }

  condition:
    any of them
}