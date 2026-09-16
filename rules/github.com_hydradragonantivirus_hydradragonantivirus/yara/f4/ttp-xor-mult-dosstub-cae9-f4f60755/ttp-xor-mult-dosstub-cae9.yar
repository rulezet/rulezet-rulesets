rule TTP_XOR_MULT_DOSStub_cae9 {
  strings:
    $key_cae9 = { 9e 81 [2] ea 99 [2] ad 9b [2] ea 8a [2] a4 86 [2] a8 8c [2] bf 87 [2] a4 c9 [2] 99 }

  condition:
    any of them
}