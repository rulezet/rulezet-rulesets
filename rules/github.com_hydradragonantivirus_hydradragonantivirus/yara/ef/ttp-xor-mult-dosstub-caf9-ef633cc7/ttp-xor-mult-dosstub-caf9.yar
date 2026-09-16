rule TTP_XOR_MULT_DOSStub_caf9 {
  strings:
    $key_caf9 = { 9e 91 [2] ea 89 [2] ad 8b [2] ea 9a [2] a4 96 [2] a8 9c [2] bf 97 [2] a4 d9 [2] 99 }

  condition:
    any of them
}