rule TTP_XOR_MULT_DOSStub_ca1f {
  strings:
    $key_ca1f = { 9e 77 [2] ea 6f [2] ad 6d [2] ea 7c [2] a4 70 [2] a8 7a [2] bf 71 [2] a4 3f [2] 99 }

  condition:
    any of them
}