rule TTP_XOR_MULT_DOSStub_ca0e {
  strings:
    $key_ca0e = { 9e 66 [2] ea 7e [2] ad 7c [2] ea 6d [2] a4 61 [2] a8 6b [2] bf 60 [2] a4 2e [2] 99 }

  condition:
    any of them
}