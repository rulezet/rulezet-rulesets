rule TTP_XOR_MULT_DOSStub_ca05 {
  strings:
    $key_ca05 = { 9e 6d [2] ea 75 [2] ad 77 [2] ea 66 [2] a4 6a [2] a8 60 [2] bf 6b [2] a4 25 [2] 99 }

  condition:
    any of them
}