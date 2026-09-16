rule TTP_XOR_MULT_DOSStub_ca74 {
  strings:
    $key_ca74 = { 9e 1c [2] ea 04 [2] ad 06 [2] ea 17 [2] a4 1b [2] a8 11 [2] bf 1a [2] a4 54 [2] 99 }

  condition:
    any of them
}