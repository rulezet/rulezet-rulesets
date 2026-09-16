rule TTP_XOR_MULT_DOSStub_ca22 {
  strings:
    $key_ca22 = { 9e 4a [2] ea 52 [2] ad 50 [2] ea 41 [2] a4 4d [2] a8 47 [2] bf 4c [2] a4 02 [2] 99 }

  condition:
    any of them
}