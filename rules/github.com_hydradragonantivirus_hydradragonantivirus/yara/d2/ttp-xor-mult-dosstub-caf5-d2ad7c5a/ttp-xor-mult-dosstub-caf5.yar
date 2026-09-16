rule TTP_XOR_MULT_DOSStub_caf5 {
  strings:
    $key_caf5 = { 9e 9d [2] ea 85 [2] ad 87 [2] ea 96 [2] a4 9a [2] a8 90 [2] bf 9b [2] a4 d5 [2] 99 }

  condition:
    any of them
}