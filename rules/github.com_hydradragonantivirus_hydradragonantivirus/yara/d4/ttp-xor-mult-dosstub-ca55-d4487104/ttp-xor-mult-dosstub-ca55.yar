rule TTP_XOR_MULT_DOSStub_ca55 {
  strings:
    $key_ca55 = { 9e 3d [2] ea 25 [2] ad 27 [2] ea 36 [2] a4 3a [2] a8 30 [2] bf 3b [2] a4 75 [2] 99 }

  condition:
    any of them
}