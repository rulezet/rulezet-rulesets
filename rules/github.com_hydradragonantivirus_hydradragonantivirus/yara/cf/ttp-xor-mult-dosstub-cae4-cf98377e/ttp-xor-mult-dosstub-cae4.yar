rule TTP_XOR_MULT_DOSStub_cae4 {
  strings:
    $key_cae4 = { 9e 8c [2] ea 94 [2] ad 96 [2] ea 87 [2] a4 8b [2] a8 81 [2] bf 8a [2] a4 c4 [2] 99 }

  condition:
    any of them
}