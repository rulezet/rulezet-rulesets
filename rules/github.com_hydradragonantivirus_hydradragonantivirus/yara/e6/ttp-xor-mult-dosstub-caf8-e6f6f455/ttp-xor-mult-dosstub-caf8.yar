rule TTP_XOR_MULT_DOSStub_caf8 {
  strings:
    $key_caf8 = { 9e 90 [2] ea 88 [2] ad 8a [2] ea 9b [2] a4 97 [2] a8 9d [2] bf 96 [2] a4 d8 [2] 99 }

  condition:
    any of them
}