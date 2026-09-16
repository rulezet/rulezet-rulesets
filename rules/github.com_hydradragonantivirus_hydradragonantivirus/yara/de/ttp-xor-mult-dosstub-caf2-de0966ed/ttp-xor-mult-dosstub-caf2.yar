rule TTP_XOR_MULT_DOSStub_caf2 {
  strings:
    $key_caf2 = { 9e 9a [2] ea 82 [2] ad 80 [2] ea 91 [2] a4 9d [2] a8 97 [2] bf 9c [2] a4 d2 [2] 99 }

  condition:
    any of them
}