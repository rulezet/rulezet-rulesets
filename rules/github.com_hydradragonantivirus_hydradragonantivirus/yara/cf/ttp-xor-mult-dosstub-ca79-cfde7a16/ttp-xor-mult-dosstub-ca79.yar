rule TTP_XOR_MULT_DOSStub_ca79 {
  strings:
    $key_ca79 = { 9e 11 [2] ea 09 [2] ad 0b [2] ea 1a [2] a4 16 [2] a8 1c [2] bf 17 [2] a4 59 [2] 99 }

  condition:
    any of them
}