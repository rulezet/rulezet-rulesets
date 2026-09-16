rule TTP_XOR_MULT_DOSStub_ca19 {
  strings:
    $key_ca19 = { 9e 71 [2] ea 69 [2] ad 6b [2] ea 7a [2] a4 76 [2] a8 7c [2] bf 77 [2] a4 39 [2] 99 }

  condition:
    any of them
}